//! SSH wire codec — milestones S1+S2+S3 of docs/git-ssh-deps.md §B.4: the
//! RFC4253 identification banner (§4.2), the binary packet framing
//! (§6, plaintext and encrypted), `SSH_MSG_KEXINIT` parse/encode
//! (§7.1) and algorithm intersection, the `curve25519-sha256` KEXDH
//! message pair (RFC4253 §8 / RFC8731 §3), the RFC4253 §7.2 key
//! derivation, `NEWKEYS`, `SSH_MSG_EXT_INFO` (RFC8308), the
//! service/`none`-auth probe messages, and (S3) the `publickey`
//! method's key/signature blobs, request payload, signing input and
//! the `PK_OK`/`SUCCESS`/`BANNER` answers (RFC4252 §7). **No primitive
//! lives here** — SHA-256, HMAC, AES-CTR, X25519 and Ed25519 all come
//! from the audited crates the kernel (and, for tests only, this
//! crate's dev-dependencies) already use; everything in this file is
//! protocol glue over a wire format the RFCs specify byte for byte.
//!
//! From-scratch under the skill's dependency-policy exception (a),
//! justified in docs/git-ssh-deps.md §B.2: `russh` is std-only
//! (`bytes`/`futures`/`aws-lc-rs` force it) and carries a 7-advisory
//! history including packet-length OOM; RustCrypto's `ssh-protocol` is
//! a 16-line WIP facade re-exporting `ssh-cipher`/`ssh-encoding`/
//! `ssh-key`; a crates.io search found no maintained no_std SSH
//! transport crate. This is protocol glue over a wire format the RFC
//! specifies byte for byte — no cryptography, no dependencies.
//!
//! `#![no_std]`, `#![forbid(unsafe_code)]`, zero dependencies, no
//! allocator: every parser consumes caller-provided buffers and every
//! encoder writes into caller-provided fixed buffers. Every path is
//! adversarially tested — [`decode_banner`] and [`decode_packet`] are
//! fed one byte at a time in the tests.
//!
//! Fail-closed by design: a refused line/packet means the connection
//! is unusable, never "skip the bad bytes and resync" (RFC4253 §4.2's
//! optional pre-banner lines are therefore *refused*, not skipped —
//! neither OpenSSH nor github.com sends them).

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// RFC4253 §4.2: the server identification string is *at most 255
/// characters **including** the trailing CRLF*. A longer line is
/// refused outright (OpenSSH's bound), not buffered.
pub const BANNER_MAX: usize = 255;

/// Our identification string, sent immediately after the TCP
/// handshake (RFC4253 §4.2: both sides send it before anything else).
pub const OUR_BANNER: &[u8] = b"SSH-2.0-reemplazo_0.1\r\n";

/// Protocols we accept on the wire: `SSH-2.0-…`, plus `SSH-1.99-…`
/// which per RFC4253 §4.2 "reads as 2.0" (a transitional marker from
/// SSH 1.99 implementations — we treat it exactly as 2.0).
const BANNER_PREFIX_V2: &[u8] = b"SSH-2.0-";
const BANNER_PREFIX_V199: &[u8] = b"SSH-1.99-";

/// Why a server identification string was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerError {
    /// Not `SSH-2.0-…`/`SSH-1.99-…` — includes `SSH-1.xx` (major
    /// version 1), non-SSH junk, and an empty software version.
    Incompatible,
    /// An LF without a preceding CR, or a CR not followed by LF —
    /// an embedded line break inside (or instead of) the CRLF.
    BadEol,
    /// A non-printable byte, or a space where the software version
    /// must be (RFC4253 §4.2: the string is printable US-ASCII, the
    /// software version contains no space).
    BadChar,
    /// No complete CRLF-terminated line within [`BANNER_MAX`] bytes.
    TooLong,
}

/// Result of one [`decode_banner`] step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BannerStep<'a> {
    /// Need more bytes (feed again).
    Incomplete,
    /// A complete, validated identification string: `consumed`
    /// includes the CRLF, `ident` excludes it (therefore ≤ 253 bytes
    /// of printable ASCII).
    Done { consumed: usize, ident: &'a [u8] },
    /// The line is malformed — stop.
    Failed(BannerError),
}

/// Decode the identification string at the front of `buf`. Strict:
/// only a complete `SSH-2.0-…`/`SSH-1.99-…` line terminated by CRLF
/// is accepted; a malformed line fails the moment it *can* fail, and
/// the line bound is enforced the moment it is exceeded. Bytes after
/// the CRLF (the server may pipeline its `KEXINIT`) are left alone —
/// `consumed` says where the line ends.
pub fn decode_banner(buf: &[u8]) -> BannerStep<'_> {
    // Scan at most the first BANNER_MAX bytes: a CRLF starting past
    // the bound cannot belong to a legal line, so if none completes
    // inside the window the line is over-long.
    let window = buf.len().min(BANNER_MAX);
    let mut i = 0usize;
    while i < window {
        match buf[i] {
            b'\r' => {
                if i + 2 > BANNER_MAX {
                    // A CRLF here could not fit in the bound.
                    return BannerStep::Failed(BannerError::TooLong);
                }
                if i + 1 >= buf.len() {
                    return BannerStep::Incomplete; // the LF may still arrive
                }
                if buf[i + 1] != b'\n' {
                    return BannerStep::Failed(BannerError::BadEol);
                }
                let ident = &buf[..i];
                return match validate_ident(ident) {
                    Ok(()) => BannerStep::Done {
                        consumed: i + 2,
                        ident,
                    },
                    Err(e) => BannerStep::Failed(e),
                };
            }
            b'\n' => return BannerStep::Failed(BannerError::BadEol), // bare LF
            _ => i += 1,
        }
    }
    // No CRLF inside the window.
    if buf.len() >= BANNER_MAX {
        BannerStep::Failed(BannerError::TooLong)
    } else {
        BannerStep::Incomplete
    }
}

/// Validate a complete line (CRLF already stripped): the version
/// prefix, at least one non-space software-version byte, and printable
/// US-ASCII throughout (comments may contain spaces).
fn validate_ident(line: &[u8]) -> Result<(), BannerError> {
    let rest: &[u8] = if line.starts_with(BANNER_PREFIX_V2) {
        &line[BANNER_PREFIX_V2.len()..]
    } else if line.starts_with(BANNER_PREFIX_V199) {
        &line[BANNER_PREFIX_V199.len()..]
    } else {
        return Err(BannerError::Incompatible);
    };
    let mut chars = rest.iter();
    let first = *chars.next().ok_or(BannerError::Incompatible)?; // empty version
    if !(0x21..=0x7E).contains(&first) {
        return Err(BannerError::BadChar); // space or control where the version goes
    }
    if chars.any(|&b| !(0x20..=0x7E).contains(&b)) {
        return Err(BannerError::BadChar);
    }
    Ok(())
}

/// `SSH_MSG_KEXINIT` (RFC4253 §7.1).
pub const SSH_MSG_KEXINIT: u8 = 20;

/// Framing cap for unencrypted packets, matching OpenSSH's limit: a
/// declared `packet_length` beyond this is refused the moment the
/// header is complete — before a single byte of the attacker-chosen
/// body is ever waited on (the S1 receive buffer is far smaller
/// anyway; a bogus huge length must not turn into a read stall).
pub const MAX_PACKET_LENGTH: u32 = 35_000;

/// Unencrypted block size (RFC4253 §6): `4 + packet_length` must be a
/// multiple of this.
pub const BLOCK_SIZE: usize = 8;

/// Minimum random padding (RFC4253 §6: "There MUST be at least four
/// bytes of padding").
pub const MIN_PADDING: usize = 4;

/// Why a binary packet header was refused. Fail-closed: a malformed
/// header means the connection is unusable — nothing may skip it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketError {
    /// `packet_length` too small to hold the mandatory bookkeeping.
    TooSmall,
    /// `packet_length` beyond [`MAX_PACKET_LENGTH`].
    TooLarge,
    /// `4 + packet_length` is not a multiple of [`BLOCK_SIZE`].
    Misaligned,
    /// `padding_length` below [`MIN_PADDING`] or running past the
    /// declared `packet_length`.
    BadPadding,
    /// Zero-length payload — no message-type byte.
    EmptyPayload,
}

/// Result of one [`decode_packet`] step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketStep<'a> {
    /// Need more bytes (feed again).
    Incomplete,
    /// One complete packet consumed from the front of `buf`:
    /// `payload` is the message body only (no length field, no
    /// `padding_length` byte, no padding).
    Done { consumed: usize, payload: &'a [u8] },
    /// The stream is malformed — stop.
    Failed(PacketError),
}

/// Decode the unencrypted binary packet at the front of `buf`
/// (RFC4253 §6: `uint32 packet_length`, `byte padding_length`,
/// `payload`, `padding`; the MAC does not exist yet in this phase and
/// `packet_length` excludes the length field itself). The header is
/// validated the moment it is complete, so a bad declared structure
/// fails before its (attacker-chosen) length is ever waited on.
pub fn decode_packet(buf: &[u8]) -> PacketStep<'_> {
    decode_packet_block(buf, BLOCK_SIZE)
}

/// [`decode_packet`] with an explicit alignment block: `8` before the
/// keys exist, `max(cipher block, 8)` once `aes*-ctr` is up (16 for
/// every cipher we negotiate — RFC4253 §6). A `block_size` of 0 is
/// refused as [`PacketError::Misaligned`] (defensive; the encoders
/// refuse blocks below [`MIN_PADDING`]'s alignment base too).
pub fn decode_packet_block(buf: &[u8], block_size: usize) -> PacketStep<'_> {
    if block_size == 0 {
        return PacketStep::Failed(PacketError::Misaligned);
    }
    if buf.len() < 4 {
        return PacketStep::Incomplete;
    }
    // `try_into` cannot fail (len == 4 just checked); the zero
    // fallback would fail `TooSmall` anyway — never an unwrap.
    let head: [u8; 4] = buf[..4].try_into().unwrap_or([0; 4]);
    let declared = u32::from_be_bytes(head);
    if declared < 5 {
        return PacketStep::Failed(PacketError::TooSmall);
    }
    if declared > MAX_PACKET_LENGTH {
        return PacketStep::Failed(PacketError::TooLarge);
    }
    // u32 → usize after the cap check: lossless on every target we
    // build for (x86-64 hosts and `x86_64-unknown-none`).
    let packet_length = declared as usize;
    if !(packet_length + 4).is_multiple_of(block_size) {
        return PacketStep::Failed(PacketError::Misaligned);
    }
    if buf.len() < 5 {
        return PacketStep::Incomplete; // the padding_length byte is not here yet
    }
    let padding_length = usize::from(buf[4]);
    if padding_length < MIN_PADDING || padding_length + 1 > packet_length {
        return PacketStep::Failed(PacketError::BadPadding);
    }
    let payload_length = packet_length - 1 - padding_length;
    if payload_length == 0 {
        return PacketStep::Failed(PacketError::EmptyPayload);
    }
    let total = 4 + packet_length;
    if buf.len() < total {
        return PacketStep::Incomplete;
    }
    PacketStep::Done {
        consumed: total,
        payload: &buf[5..5 + payload_length],
    }
}

/// Why a `SSH_MSG_KEXINIT` payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexError {
    /// The message-type byte is not [`SSH_MSG_KEXINIT`].
    WrongMessage,
    /// A field runs past the payload (or the payload is empty).
    Truncated,
    /// A negotiation-relevant name-list is empty (languages may be
    /// empty — RFC4253 §7.1, they are never negotiated).
    EmptyList,
    /// Illegal byte in a name-list: control/non-ASCII byte, a space,
    /// or an empty name (`,,`, leading/trailing comma). Names are
    /// RFC4251 `name-string`s plus the `@` of vendor variants.
    BadNameList,
    /// `first_kex_packet_follows` is not 0 or 1 (RFC4251 boolean).
    BadBoolean,
    /// Bytes after the reserved uint32 — nothing legal follows it.
    TrailingGarbage,
}

/// A parsed `SSH_MSG_KEXINIT` (RFC4253 §7.1). All lists are slices of
/// the caller's payload buffer: `uint32 len` prefixes and the comma
/// structure are validated, the bytes themselves are not copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KexInit<'a> {
    /// The 16-byte opaque cookie.
    pub cookie: &'a [u8],
    pub kex_algorithms: &'a [u8],
    pub server_host_key_algorithms: &'a [u8],
    pub encryption_algorithms_c2s: &'a [u8],
    pub encryption_algorithms_s2c: &'a [u8],
    pub mac_algorithms_c2s: &'a [u8],
    pub mac_algorithms_s2c: &'a [u8],
    pub compression_algorithms_c2s: &'a [u8],
    pub compression_algorithms_s2c: &'a [u8],
    pub language_c2s: &'a [u8],
    pub language_s2c: &'a [u8],
    /// Recorded, never acted on in S1 (RFC4253 §7.1: if true the
    /// sender guessed a KEX packet would follow immediately).
    pub first_kex_packet_follows: bool,
    /// Reserved (RFC says the receiver must ignore it) — recorded.
    pub reserved: u32,
}

/// Bounds-checked cursor over the payload — every read is checked
/// against the remaining slice; wire data never reaches an unguarded
/// index.
#[derive(Debug, Clone, Copy)]
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KexError> {
        let end = self.pos.checked_add(n).ok_or(KexError::Truncated)?;
        let bytes = self.buf.get(self.pos..end).ok_or(KexError::Truncated)?;
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, KexError> {
        Ok(*self.take(1)?.first().ok_or(KexError::Truncated)?)
    }

    fn u32(&mut self) -> Result<u32, KexError> {
        let arr: [u8; 4] = self.take(4)?.try_into().map_err(|_| KexError::Truncated)?;
        Ok(u32::from_be_bytes(arr))
    }

    fn namelist(&mut self, required: bool) -> Result<&'a [u8], KexError> {
        let len = self.u32()?;
        // u32 → usize, checked rather than `as`-cast.
        let len = usize::try_from(len).map_err(|_| KexError::Truncated)?;
        let list = self.take(len)?;
        if required && list.is_empty() {
            return Err(KexError::EmptyList);
        }
        validate_namelist(list)?;
        Ok(list)
    }
}

/// A name-list is `uint32 len` + comma-separated `name-string`s:
/// non-empty names of alphanumeric plus `-._@` (RFC4251 name chars,
/// extended by every deployed vendor id like `…@openssh.com`/
/// `…@libssh.org`). Spaces, controls, non-ASCII and empty names are
/// all refused — this parser's output feeds the negotiation directly.
fn validate_namelist(list: &[u8]) -> Result<(), KexError> {
    if list.is_empty() {
        return Ok(()); // required-ness is the caller's call
    }
    let mut name_start = 0usize;
    for (i, &b) in list.iter().enumerate() {
        if b == b',' {
            if i == name_start {
                return Err(KexError::BadNameList); // `,,` or leading comma
            }
            name_start = i + 1;
        } else if !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'@')) {
            return Err(KexError::BadNameList);
        }
    }
    if name_start == list.len() {
        return Err(KexError::BadNameList); // trailing comma
    }
    Ok(())
}

/// Parse a complete `SSH_MSG_KEXINIT` packet **payload** (the message
/// type byte included — hand it [`PacketStep`]'s `payload`).
pub fn parse_kexinit(payload: &[u8]) -> Result<KexInit<'_>, KexError> {
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8()? != SSH_MSG_KEXINIT {
        return Err(KexError::WrongMessage);
    }
    let cookie = r.take(16)?;
    let kex_algorithms = r.namelist(true)?;
    let server_host_key_algorithms = r.namelist(true)?;
    let encryption_algorithms_c2s = r.namelist(true)?;
    let encryption_algorithms_s2c = r.namelist(true)?;
    let mac_algorithms_c2s = r.namelist(true)?;
    let mac_algorithms_s2c = r.namelist(true)?;
    let compression_algorithms_c2s = r.namelist(true)?;
    let compression_algorithms_s2c = r.namelist(true)?;
    let language_c2s = r.namelist(false)?;
    let language_s2c = r.namelist(false)?;
    let first_kex_packet_follows = match r.u8()? {
        0 => false,
        1 => true,
        _ => return Err(KexError::BadBoolean),
    };
    let reserved = r.u32()?;
    if r.pos != payload.len() {
        return Err(KexError::TrailingGarbage);
    }
    Ok(KexInit {
        cookie,
        kex_algorithms,
        server_host_key_algorithms,
        encryption_algorithms_c2s,
        encryption_algorithms_s2c,
        mac_algorithms_c2s,
        mac_algorithms_s2c,
        compression_algorithms_c2s,
        compression_algorithms_s2c,
        language_c2s,
        language_s2c,
        first_kex_packet_follows,
        reserved,
    })
}

/// Our kex name-list (docs/git-ssh-deps.md §B.3: the minimal
/// GitHub-compatible set — every algorithm here must be understood by
/// `github.com:22` today). `ext-info-c` is not a key-exchange method:
/// it is the RFC8308 signal that makes the server send
/// `SSH_MSG_EXT_INFO` after its `NEWKEYS` (the first encrypted packet
/// we may receive — the S2 driver parses it).
pub const KEX_ALGORITHMS: &str = "curve25519-sha256,ext-info-c";
/// The one key-exchange method we actually implement: what
/// [`intersect`] must select from [`KEX_ALGORITHMS`] (the trailing
/// `ext-info-c` signal may never be negotiated *as* the kex —
/// [`check_must_have`] refuses that).
pub const KEX_CHOSEN: &str = "curve25519-sha256";
/// Our server-host-key acceptance list.
pub const HOST_KEY_ALGORITHMS: &str = "ssh-ed25519";
/// Our cipher list, both directions (AES-CTR is a stream cipher — no
/// block-mode padding; the HMAC covers the sequence).
pub const ENCRYPTION_ALGORITHMS: &str = "aes128-ctr,aes256-ctr";
/// Our MAC list, both directions (`hmac-sha1` was removed by GitHub
/// anyway — never offer SHA-1).
pub const MAC_ALGORITHMS: &str = "hmac-sha2-256";
/// Our compression list, both directions.
pub const COMPRESSION_ALGORITHMS: &str = "none";

/// The ten name-lists we send, in RFC4253 §7.1 wire order (language
/// lists are always empty: RFC4253 §7.1 says they are not negotiated).
const OUR_LISTS: [&str; 10] = [
    KEX_ALGORITHMS,
    HOST_KEY_ALGORITHMS,
    ENCRYPTION_ALGORITHMS,
    ENCRYPTION_ALGORITHMS,
    MAC_ALGORITHMS,
    MAC_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
    "",
    "",
];

/// Bound on our own framed KEXINIT: the payload built from
/// [`OUR_LISTS`] is 166 bytes, so the whole packet is 176 bytes —
/// [`encode_kexinit`] refuses any `out` smaller than the packet needs,
/// and any `out` of this size always suffices.
pub const KEXINIT_WIRE_MAX: usize = 512;

/// Encode our `SSH_MSG_KEXINIT` as a ready-to-send **unencrypted binary
/// packet** (framing per RFC4253 §6: `packet_length` excludes itself,
/// the total is a multiple of 8, padding ≥ 4) into `out`; `None` when
/// it does not fit. `cookie` is the 16-byte random field — filled by
/// the kernel from the CSPRNG (RFC4253 §7.1: "RANDOM values"), never
/// zeros.
///
/// The padding bytes are zero-filled: S1 exchanges no secrets, so
/// padding carries no information yet (RFC's "SHOULD be random"
/// becomes a hard requirement with S2's encrypted phase, where the
/// encoder grows a caller-provided random-padding input — no RNG in
/// this zero-dependency codec).
pub fn encode_kexinit(cookie: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    encode_kexinit_lists(OUR_LISTS, cookie, out)
}

/// Does the comma-separated name-list `list` contain `name`?
/// (An empty `name` never matches.)
pub fn namelist_contains(list: &[u8], name: &[u8]) -> bool {
    !name.is_empty() && list.split(|&b| b == b',').any(|seg| seg == name)
}

/// The first name in the **client's** list that also appears in the
/// server's list (RFC4253 §7.1: client preference order wins — not
/// the server's). `None` = no overlap.
pub fn first_common<'a>(client: &'a [u8], server: &[u8]) -> Option<&'a str> {
    client
        .split(|&b| b == b',')
        .find(|seg| !seg.is_empty() && namelist_contains(server, seg))
        .and_then(|seg| core::str::from_utf8(seg).ok())
}

/// What both sides agreed on — one entry per negotiated field
/// (language lists are never negotiated, RFC4253 §7.1). `None` for a
/// field means no overlap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    pub kex: Option<&'static str>,
    pub host_key: Option<&'static str>,
    pub enc_c2s: Option<&'static str>,
    pub enc_s2c: Option<&'static str>,
    pub mac_c2s: Option<&'static str>,
    pub mac_s2c: Option<&'static str>,
    pub comp_c2s: Option<&'static str>,
    pub comp_s2c: Option<&'static str>,
}

/// Intersect the server's KEXINIT with **our** fixed lists per
/// RFC4253 §7.1 (first client-side match wins, each direction
/// negotiated independently).
pub fn intersect(server: &KexInit<'_>) -> Negotiated {
    Negotiated {
        kex: first_common(KEX_ALGORITHMS.as_bytes(), server.kex_algorithms),
        host_key: first_common(
            HOST_KEY_ALGORITHMS.as_bytes(),
            server.server_host_key_algorithms,
        ),
        enc_c2s: first_common(
            ENCRYPTION_ALGORITHMS.as_bytes(),
            server.encryption_algorithms_c2s,
        ),
        enc_s2c: first_common(
            ENCRYPTION_ALGORITHMS.as_bytes(),
            server.encryption_algorithms_s2c,
        ),
        mac_c2s: first_common(MAC_ALGORITHMS.as_bytes(), server.mac_algorithms_c2s),
        mac_s2c: first_common(MAC_ALGORITHMS.as_bytes(), server.mac_algorithms_s2c),
        comp_c2s: first_common(
            COMPRESSION_ALGORITHMS.as_bytes(),
            server.compression_algorithms_c2s,
        ),
        comp_s2c: first_common(
            COMPRESSION_ALGORITHMS.as_bytes(),
            server.compression_algorithms_s2c,
        ),
    }
}

/// Which must-have agreement is missing (docs/git-ssh-deps.md §B.3 —
/// S1 fails closed on any of them; there is no "continue anyway").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    Kex,
    HostKey,
    EncC2s,
    EncS2c,
    MacC2s,
    MacS2c,
    CompC2s,
    CompS2c,
}

impl Missing {
    /// Human-readable label for the fatal log line.
    pub fn as_str(self) -> &'static str {
        match self {
            Missing::Kex => "kex algorithms (need curve25519-sha256)",
            Missing::HostKey => "host key algorithms (need ssh-ed25519)",
            Missing::EncC2s => "client-to-server cipher (need aes128-ctr/aes256-ctr)",
            Missing::EncS2c => "server-to-client cipher (need aes128-ctr/aes256-ctr)",
            Missing::MacC2s => "client-to-server MAC (need hmac-sha2-256)",
            Missing::MacS2c => "server-to-client MAC (need hmac-sha2-256)",
            Missing::CompC2s => "client-to-server compression (need none)",
            Missing::CompS2c => "server-to-client compression (need none)",
        }
    }
}

/// The S1 gate: every negotiated field must hold an algorithm we can
/// actually implement (§B.1 primitives + `none`). Anything else —
/// including missing overlap — is a hard failure.
pub fn check_must_have(n: &Negotiated) -> Result<(), Missing> {
    if n.kex != Some(KEX_CHOSEN) {
        return Err(Missing::Kex);
    }
    if n.host_key != Some(HOST_KEY_ALGORITHMS) {
        return Err(Missing::HostKey);
    }
    match n.enc_c2s {
        Some("aes128-ctr") | Some("aes256-ctr") => {}
        _ => return Err(Missing::EncC2s),
    }
    match n.enc_s2c {
        Some("aes128-ctr") | Some("aes256-ctr") => {}
        _ => return Err(Missing::EncS2c),
    }
    if n.mac_c2s != Some(MAC_ALGORITHMS) {
        return Err(Missing::MacC2s);
    }
    if n.mac_s2c != Some(MAC_ALGORITHMS) {
        return Err(Missing::MacS2c);
    }
    if n.comp_c2s != Some(COMPRESSION_ALGORITHMS) {
        return Err(Missing::CompC2s);
    }
    if n.comp_s2c != Some(COMPRESSION_ALGORITHMS) {
        return Err(Missing::CompS2c);
    }
    Ok(())
}

// ---- S2: key exchange, key derivation, encrypted packets ----------

/// `SSH_MSG_EXT_INFO` (RFC8308 §2.1) — may arrive as the first
/// encrypted packet after the server's `NEWKEYS`.
pub const SSH_MSG_EXT_INFO: u8 = 7;
/// `SSH_MSG_SERVICE_REQUEST` (RFC4253 §10).
pub const SSH_MSG_SERVICE_REQUEST: u8 = 5;
/// `SSH_MSG_SERVICE_ACCEPT` (RFC4253 §10).
pub const SSH_MSG_SERVICE_ACCEPT: u8 = 6;
/// `SSH_MSG_NEWKEYS` (RFC4253 §7.3).
pub const SSH_MSG_NEWKEYS: u8 = 21;
/// `SSH_MSG_KEXDH_INIT` — RFC8731 §3 registers the curve25519 method
/// under the ECDH message numbers, identical to RFC4253 §8's.
pub const SSH_MSG_KEXDH_INIT: u8 = 30;
/// `SSH_MSG_KEXDH_REPLY` (RFC8731 §3 / RFC4253 §8).
pub const SSH_MSG_KEXDH_REPLY: u8 = 31;
/// `SSH_MSG_USERAUTH_REQUEST` (RFC4254 §5).
pub const SSH_MSG_USERAUTH_REQUEST: u8 = 50;
/// `SSH_MSG_USERAUTH_FAILURE` (RFC4252 §5.1 — field order: name-list,
/// then the `partial success` boolean).
pub const SSH_MSG_USERAUTH_FAILURE: u8 = 51;
/// `SSH_MSG_USERAUTH_SUCCESS` (RFC4252 §5.1) — a bare message byte.
pub const SSH_MSG_USERAUTH_SUCCESS: u8 = 52;
/// `SSH_MSG_USERAUTH_BANNER` (RFC4252 §5.4) — may arrive at any point
/// during authentication.
pub const SSH_MSG_USERAUTH_BANNER: u8 = 53;
/// `SSH_MSG_USERAUTH_PK_OK` (RFC4252 §7) — "this key would be
/// acceptable, send the signature" (message number 60).
pub const SSH_MSG_USERAUTH_PK_OK: u8 = 60;

/// `hmac-sha2-256` tag length (RFC4253 §6.4 over SHA-256): every MAC
/// on the wire is exactly this many bytes, in the clear after the
/// ciphertext.
pub const TAG_LEN: usize = 32;
/// Encrypted-phase alignment block: `max(cipher block, 8)` for the
/// `aes*-ctr` family is 16 (RFC4253 §6 — the constraint holds even
/// for stream ciphers).
pub const ENC_BLOCK: usize = 16;

/// RFC4251 `string`: `uint32` big-endian length + bytes. `None` when
/// it does not fit `out` (or the length exceeds `u32::MAX`).
pub fn encode_string(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let n = u32::try_from(bytes.len()).ok()?;
    let total = 4usize.checked_add(bytes.len())?;
    let dst = out.get_mut(..total)?;
    dst[..4].copy_from_slice(&n.to_be_bytes());
    dst[4..].copy_from_slice(bytes);
    Some(total)
}

/// RFC4251 `mpint` of a non-negative integer: leading zero bytes are
/// stripped, `0x00` is prepended when the leading bit would make the
/// value negative, and the `uint32` length counts that prepended byte.
/// Byte-for-byte identical to OpenSSH's `sshbuf_put_bignum2_bytes` —
/// the exchange hash and the RFC4253 §7.2 KDF both feed this encoding
/// of the shared secret `K`, so a single divergent byte breaks every
/// signature and key. `None` when it does not fit `out`.
pub fn encode_mpint(bytes: &[u8], out: &mut [u8]) -> Option<usize> {
    let start = bytes.iter().take_while(|&&b| b == 0).count();
    let body = &bytes[start..];
    let prepend = matches!(body.first(), Some(&b) if b & 0x80 != 0);
    let n = body.len() + usize::from(prepend);
    let n32 = u32::try_from(n).ok()?;
    let total = 4usize.checked_add(n)?;
    let dst = out.get_mut(..total)?;
    dst[..4].copy_from_slice(&n32.to_be_bytes());
    let mut w = 4;
    if prepend {
        dst[w] = 0;
        w += 1;
    }
    dst[w..].copy_from_slice(body);
    Some(total)
}

/// Frame `payload` as one binary packet (RFC4253 §6): `uint32
/// packet_length`, `byte padding_length`, `payload`, padding — with
/// `4 + packet_length` a multiple of `block_size` (≥ 8, per
/// `max(cipher block, 8)`) and at least [`MIN_PADDING`] padding bytes.
/// The padding is whatever `fill_pad` writes — S2 draws random bytes
/// from the kernel CSPRNG (the RFC's "SHOULD be random" is a hard
/// requirement once padding rides inside ciphertext); S1's KEXINIT
/// encoder still zero-fills deliberately, because it carries no
/// secrets. `None` when the packet does not fit `out`, `payload` is
/// empty (no message-type byte), or `block_size` is unusable. MAC and
/// encryption are [`seal_packet`]'s job.
pub fn encode_packet(
    payload: &[u8],
    block_size: usize,
    mut fill_pad: impl FnMut(&mut [u8]),
    out: &mut [u8],
) -> Option<usize> {
    if payload.is_empty() || block_size < 8 {
        return None;
    }
    let unpadded = 5usize.checked_add(payload.len())?;
    let mut pad = (block_size - unpadded % block_size) % block_size;
    if pad < MIN_PADDING {
        pad += block_size;
    }
    // `padding_length` is a single byte (RFC4253 §6).
    if pad > u8::MAX as usize {
        return None;
    }
    let packet_length = 1usize.checked_add(payload.len())?.checked_add(pad)?;
    let packet_length32 = u32::try_from(packet_length).ok()?;
    let total = 4usize.checked_add(packet_length)?;
    let dst = out.get_mut(..total)?;
    dst[..4].copy_from_slice(&packet_length32.to_be_bytes());
    dst[4] = u8::try_from(pad).ok()?;
    dst[5..5 + payload.len()].copy_from_slice(payload);
    fill_pad(&mut dst[5 + payload.len()..total]);
    Some(total)
}

/// The wire length (`4 + packet_length`) declared by a packet header,
/// validated against `block_size`, from just the first four bytes.
/// The encrypted phase needs this after decrypting only the first
/// block-aligned chunk: the length itself is ciphertext, and it says
/// where the ciphertext ends and the in-the-clear MAC tag begins
/// (RFC4253 §6.3). `Ok(None)` while fewer than four bytes exist;
/// `Err` the moment the header alone is illegal — bounds are checked
/// before a single further byte is ever waited on.
pub fn packet_total(head: &[u8], block_size: usize) -> Result<Option<usize>, PacketError> {
    if block_size == 0 {
        return Err(PacketError::Misaligned);
    }
    let Some(first) = head.get(..4) else {
        return Ok(None);
    };
    let arr: [u8; 4] = first.try_into().map_err(|_| PacketError::TooSmall)?;
    let declared = u32::from_be_bytes(arr);
    if declared < 5 {
        return Err(PacketError::TooSmall);
    }
    if declared > MAX_PACKET_LENGTH {
        return Err(PacketError::TooLarge);
    }
    // u32 → usize after the cap check (lossless on our targets).
    let total = 4usize
        .checked_add(declared as usize)
        .ok_or(PacketError::TooLarge)?;
    if !total.is_multiple_of(block_size) {
        return Err(PacketError::Misaligned);
    }
    Ok(Some(total))
}

/// A parsed `SSH_MSG_KEXDH_REPLY` (RFC4253 §8 / RFC8731 §3). Every
/// length has been validated: `K_S` is exactly `string "ssh-ed25519"`
/// followed by `string` of 32 key bytes, `f` exactly 32 bytes and not
/// the all-zero (small-order) point, `signature` exactly
/// `string "ssh-ed25519"` followed by `string` of 64 bytes. Slices
/// point into the caller's payload buffer — nothing is copied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KexDhReply<'a> {
    /// The host-key blob `K_S` as it will be hashed (the whole blob,
    /// `string`-encoded into the exchange hash).
    pub host_key: &'a [u8],
    /// The raw 32-byte ed25519 public key inside `K_S` — verify the
    /// signature with it, then pin it.
    pub host_key_bytes: &'a [u8],
    /// The server's 32-byte ephemeral public value `f`.
    pub f: &'a [u8],
    /// The signature blob as it appears on the wire (`string
    /// "ssh-ed25519" || string` of 64 bytes).
    pub signature: &'a [u8],
    /// The raw 64-byte ed25519 signature inside `signature` — this is
    /// what verifies the exchange hash.
    pub signature_bytes: &'a [u8],
}

/// Why a `SSH_MSG_KEXDH_REPLY` payload was refused. Fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KexDhError {
    /// Not [`SSH_MSG_KEXDH_REPLY`].
    WrongMessage,
    /// A field runs past the payload (or it is empty).
    Truncated,
    /// `K_S` is not `string "ssh-ed25519" || string` of exactly 32
    /// key bytes (we negotiate only `ssh-ed25519`, docs §B.3).
    BadHostKey,
    /// `f` is not exactly 32 bytes (RFC8731 §3: abort on any other
    /// length).
    BadPublicKey,
    /// `f` is the all-zero point — small-order, the shared secret
    /// would be all zero (RFC8731 §3 / RFC7748 §6).
    ZeroPublicKey,
    /// The signature blob is not `string "ssh-ed25519" || string` of
    /// exactly 64 bytes.
    BadSignature,
    /// Bytes after the signature — nothing legal follows it.
    TrailingGarbage,
}

/// Parse a complete `SSH_MSG_KEXDH_REPLY` **payload** (message byte
/// included — hand it the `payload` a `PacketStep` produced).
pub fn parse_kexdh_reply(payload: &[u8]) -> Result<KexDhReply<'_>, KexDhError> {
    let read = |e: KexError| match e {
        KexError::Truncated => KexDhError::Truncated,
        // `Reader::take/u8/u32` only ever fail with Truncated.
        _ => KexDhError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_KEXDH_REPLY {
        return Err(KexDhError::WrongMessage);
    }
    // K_S: outer string, then string "ssh-ed25519" + string 32.
    let ks_len = r.u32().map_err(read)?;
    let ks_len = usize::try_from(ks_len).map_err(|_| KexDhError::Truncated)?;
    let host_key = r.take(ks_len).map_err(read)?;
    let mut inner = Reader {
        buf: host_key,
        pos: 0,
    };
    let ks_alg_len = inner.u32().map_err(read)?;
    if ks_alg_len != 11 || inner.take(11).map_err(read)? != b"ssh-ed25519" {
        return Err(KexDhError::BadHostKey);
    }
    let key_len = inner.u32().map_err(read)?;
    if key_len != 32 {
        return Err(KexDhError::BadHostKey);
    }
    let host_key_bytes = inner.take(32).map_err(read)?;
    if inner.pos != host_key.len() {
        return Err(KexDhError::BadHostKey);
    }
    // f: string of exactly 32 bytes, not all-zero.
    let f_len = r.u32().map_err(read)?;
    if f_len != 32 {
        return Err(KexDhError::BadPublicKey);
    }
    let f = r.take(32).map_err(read)?;
    if f.iter().all(|&b| b == 0) {
        return Err(KexDhError::ZeroPublicKey);
    }
    // signature: outer string, then string "ssh-ed25519" + string 64.
    let sig_len = r.u32().map_err(read)?;
    let sig_len = usize::try_from(sig_len).map_err(|_| KexDhError::Truncated)?;
    let signature = r.take(sig_len).map_err(read)?;
    let mut inner = Reader {
        buf: signature,
        pos: 0,
    };
    let sig_alg_len = inner.u32().map_err(read)?;
    if sig_alg_len != 11 || inner.take(11).map_err(read)? != b"ssh-ed25519" {
        return Err(KexDhError::BadSignature);
    }
    let sig_inner_len = inner.u32().map_err(read)?;
    if sig_inner_len != 64 {
        return Err(KexDhError::BadSignature);
    }
    let signature_bytes = inner.take(64).map_err(read)?;
    if inner.pos != signature.len() {
        return Err(KexDhError::BadSignature);
    }
    if r.pos != payload.len() {
        return Err(KexDhError::TrailingGarbage);
    }
    Ok(KexDhReply {
        host_key,
        host_key_bytes,
        f,
        signature,
        signature_bytes,
    })
}

/// Bound on one `SSH_MSG_EXT_INFO`: OpenSSH allows 1024 entries; a
/// client that never rekeys needs a handful (GitHub sends four). The
/// count is refused the moment it exceeds this — before any entry is
/// parsed, so a hostile `uint32` never becomes work.
pub const EXT_INFO_MAX: usize = 64;

/// Why an `SSH_MSG_EXT_INFO` payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtInfoError {
    /// Not [`SSH_MSG_EXT_INFO`].
    WrongMessage,
    /// A field runs past the payload.
    Truncated,
    /// Declared entry count above [`EXT_INFO_MAX`].
    TooMany,
    /// An extension name is empty or contains non-graphic bytes
    /// (values are opaque; the kernel sanitizes before logging).
    BadName,
    /// Bytes after the declared entries.
    TrailingGarbage,
}

/// One `(name, value)` extension pair from an [`ExtInfo`] cursor.
pub type ExtEntry<'a> = (&'a [u8], &'a [u8]);

/// A bounded cursor over the entries of a parsed `SSH_MSG_EXT_INFO`
/// (RFC8308 §2.1): `uint32 nr-extension` followed by `nr` × (`string
/// name`, `string value`). Drive it with [`ExtInfo::next_entry`]
/// until `Ok(None)`, then [`ExtInfo::finish`] proves nothing follows.
#[derive(Debug, Clone, Copy)]
pub struct ExtInfo<'a> {
    r: Reader<'a>,
    left: usize,
}

/// Parse the header of a complete `SSH_MSG_EXT_INFO` **payload**
/// (message byte included).
pub fn parse_ext_info(payload: &[u8]) -> Result<ExtInfo<'_>, ExtInfoError> {
    let read = |e: KexError| match e {
        KexError::Truncated => ExtInfoError::Truncated,
        _ => ExtInfoError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_EXT_INFO {
        return Err(ExtInfoError::WrongMessage);
    }
    let count = r.u32().map_err(read)?;
    if count > EXT_INFO_MAX as u32 {
        return Err(ExtInfoError::TooMany);
    }
    Ok(ExtInfo {
        r,
        left: count as usize,
    })
}

impl<'a> ExtInfo<'a> {
    /// The next `(name, value)`; `Ok(None)` once the declared count
    /// is exhausted.
    pub fn next_entry(&mut self) -> Result<Option<ExtEntry<'a>>, ExtInfoError> {
        if self.left == 0 {
            return Ok(None);
        }
        let read = |e: KexError| match e {
            KexError::Truncated => ExtInfoError::Truncated,
            _ => ExtInfoError::Truncated,
        };
        let nlen = self.r.u32().map_err(read)?;
        let nlen = usize::try_from(nlen).map_err(|_| ExtInfoError::Truncated)?;
        let name = self.r.take(nlen).map_err(read)?;
        // RFC8308 extension names are short printable tokens; an
        // empty or control-byte name is refused, a value is opaque.
        if name.is_empty() || !name.iter().all(|&b| (0x21..=0x7E).contains(&b)) {
            return Err(ExtInfoError::BadName);
        }
        let vlen = self.r.u32().map_err(read)?;
        let vlen = usize::try_from(vlen).map_err(|_| ExtInfoError::Truncated)?;
        let value = self.r.take(vlen).map_err(read)?;
        self.left -= 1;
        Ok(Some((name, value)))
    }
    /// Nothing may follow the declared entries.
    pub fn finish(self) -> Result<(), ExtInfoError> {
        if self.r.pos != self.r.buf.len() {
            return Err(ExtInfoError::TrailingGarbage);
        }
        Ok(())
    }
}

/// A parsed `SSH_MSG_USERAUTH_FAILURE` (RFC4254 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAuthFailure<'a> {
    /// `partial_success` — the `none` probe must come back `false`
    /// (GitHub never accepts `none`; `true` would mean something is
    /// very wrong).
    pub partial_success: bool,
    /// The offered-methods name-list (comma-separated, sanitized by
    /// the kernel before any log line).
    pub methods: &'a [u8],
}

/// Why a `SSH_MSG_USERAUTH_FAILURE` payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserAuthError {
    /// Not the expected message type.
    WrongMessage,
    /// A field runs past the payload.
    Truncated,
    /// `partial_success` is not 0 or 1 (RFC4251 boolean).
    BadBoolean,
    /// Illegal byte in the methods name-list (same rules as the
    /// KEXINIT lists).
    BadNameList,
    /// Bytes after the last field.
    TrailingGarbage,
    /// A `publickey` answer names an algorithm other than
    /// [`ED25519`] — we only ever send that one.
    WrongAlgorithm,
    /// `SSH_MSG_USERAUTH_PK_OK` echoed a blob that is not a
    /// well-formed `ssh-ed25519` public key.
    BadKey,
    /// A `publickey` request carried a signature blob that is not
    /// `string "ssh-ed25519" || string` of 64 bytes.
    BadSignature,
    /// A well-formed request for an auth method this server does not
    /// implement (anything but `none`/`publickey`).
    UnsupportedMethod,
}

/// Parse a complete `SSH_MSG_USERAUTH_FAILURE` **payload** (message
/// byte included). Field order is **RFC4252 §5.1**: the name-list
/// comes FIRST, then the boolean — the opposite of what many readers
/// assume from RFC4254 (which does not define this message); GitHub's
/// server and OpenSSH's client both use this order.
pub fn parse_userauth_failure(payload: &[u8]) -> Result<UserAuthFailure<'_>, UserAuthError> {
    let read = |e: KexError| match e {
        KexError::Truncated => UserAuthError::Truncated,
        KexError::BadNameList => UserAuthError::BadNameList,
        // `namelist(false)` never reports EmptyList.
        _ => UserAuthError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_USERAUTH_FAILURE {
        return Err(UserAuthError::WrongMessage);
    }
    // RFC4252 §5.1: name-list, THEN boolean.
    let methods = r.namelist(false).map_err(read)?;
    let partial_success = match r.u8().map_err(read)? {
        0 => false,
        1 => true,
        _ => return Err(UserAuthError::BadBoolean),
    };
    if r.pos != payload.len() {
        return Err(UserAuthError::TrailingGarbage);
    }
    Ok(UserAuthFailure {
        partial_success,
        methods,
    })
}

/// Why a `SSH_MSG_SERVICE_ACCEPT` payload was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceError {
    /// Not [`SSH_MSG_SERVICE_ACCEPT`].
    WrongMessage,
    /// The service-name string runs past the payload.
    Truncated,
    /// Bytes after the service-name string.
    TrailingGarbage,
}

/// Parse a complete `SSH_MSG_SERVICE_ACCEPT` **payload**, returning
/// the accepted service name (`string`). The caller checks it is
/// `"ssh-userauth"`.
pub fn parse_service_accept(payload: &[u8]) -> Result<&[u8], ServiceError> {
    let read = |e: KexError| match e {
        KexError::Truncated => ServiceError::Truncated,
        _ => ServiceError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_SERVICE_ACCEPT {
        return Err(ServiceError::WrongMessage);
    }
    let nlen = r.u32().map_err(read)?;
    let nlen = usize::try_from(nlen).map_err(|_| ServiceError::Truncated)?;
    let name = r.take(nlen).map_err(read)?;
    if r.pos != payload.len() {
        return Err(ServiceError::TrailingGarbage);
    }
    Ok(name)
}

/// The `SSH_MSG_KEXDH_INIT` payload (RFC8731 §3): message byte +
/// `string` of the client's 32-byte ephemeral public value.
pub fn kexdh_init_payload(e: &[u8; 32], out: &mut [u8]) -> Option<usize> {
    let dst = out.get_mut(..1 + 4 + 32)?;
    dst[0] = SSH_MSG_KEXDH_INIT;
    let n = encode_string(e, &mut dst[1..])?;
    Some(1 + n)
}

/// The `SSH_MSG_SERVICE_REQUEST` payload for `"ssh-userauth"`
/// (RFC4253 §10).
pub fn service_request_payload(out: &mut [u8]) -> Option<usize> {
    const SERVICE: &[u8] = b"ssh-userauth";
    let dst = out.get_mut(..1 + 4 + SERVICE.len())?;
    dst[0] = SSH_MSG_SERVICE_REQUEST;
    let n = encode_string(SERVICE, &mut dst[1..])?;
    Some(1 + n)
}

/// The `SSH_MSG_USERAUTH_REQUEST` payload with method `"none"` for
/// user `git` on service `ssh-connection` (RFC4254 §5) — the pre-auth
/// probe whose `SSH_MSG_USERAUTH_FAILURE` proves the whole encrypted
/// path. The user name is irrelevant to GitHub for a `none` probe; it
/// is fixed (and byte-tested) rather than configurable.
pub fn userauth_none_payload(out: &mut [u8]) -> Option<usize> {
    // 1 + (4+3) + (4+14) + (4+4) = 34 bytes exactly.
    let dst = out.get_mut(..34)?;
    let mut w = 0usize;
    dst[w] = SSH_MSG_USERAUTH_REQUEST;
    w += 1;
    w += encode_string(b"git", &mut dst[w..])?;
    w += encode_string(b"ssh-connection", &mut dst[w..])?;
    w += encode_string(b"none", &mut dst[w..])?;
    Some(w)
}

// --- S3: `publickey` authentication with `ssh-ed25519` (RFC4252 §7) ---
//
// Everything below is **encoding**, not cryptography: the blob shapes,
// the request payload and the "session_id || request" signing input are
// RFC4251/RFC4252 field layouts. The signature itself is produced and
// verified by `ed25519-dalek` in the kernel (and, for the host tests
// below, by the same audited crate as a dev-dependency) — this crate
// never touches key material beyond copying bytes into caller buffers.

/// The `publickey` method name (RFC4252 §7).
pub const AUTH_METHOD_PUBLICKEY: &[u8] = b"publickey";
/// The service every user-auth request names (RFC4252 §5).
pub const AUTH_SERVICE: &[u8] = b"ssh-connection";
/// The user this client authenticates as. GitHub identifies the
/// account by the key, not by the user name (any name works); it is
/// fixed so the signed request is reproducible and byte-tested.
pub const AUTH_USER: &[u8] = b"git";
/// The only public-key algorithm we negotiate, accept and sign with
/// (docs/git-ssh-deps.md §B.3).
pub const ED25519: &[u8] = b"ssh-ed25519";
/// Raw ed25519 public keys and signatures are exactly these lengths.
pub const ED25519_KEY_LEN: usize = 32;
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Wire length of `string "ssh-ed25519" || string <key>`, the public
/// key *blob* (the same shape as `K_S` in RFC4253 §8).
pub const ED25519_KEY_BLOB_LEN: usize = 4 + ED25519.len() + 4 + ED25519_KEY_LEN;
/// Wire length of `string "ssh-ed25519" || string <signature>`.
pub const ED25519_SIG_BLOB_LEN: usize = 4 + ED25519.len() + 4 + ED25519_SIGNATURE_LEN;

/// Why a key/signature blob or a hex seed was refused. Fail-closed:
/// every variant means "do not use this key".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// A field runs past the blob (or the blob is empty).
    Truncated,
    /// The algorithm string is not [`ED25519`].
    WrongAlgorithm,
    /// The key/signature is not exactly 32/64 bytes.
    BadLength,
    /// Bytes after the last field — nothing legal follows it.
    TrailingGarbage,
    /// A hex seed is not exactly 64 hex digits (after ASCII whitespace
    /// trimming).
    BadHexLength,
    /// A hex seed contains a non-hex-digit byte.
    NotHex,
    /// An `authorized_keys` base64 body is not strict RFC4648 base64.
    NotBase64,
}

/// Encode `string "ssh-ed25519" || string <key>` — the public-key blob
/// used as `K_S` (RFC4253 §8), in `authorized_keys`, and as the
/// key-blob field of a `publickey` request. Callers that put it on the
/// wire wrap it again in a `string`.
pub fn ed25519_key_blob(key: &[u8; ED25519_KEY_LEN], out: &mut [u8]) -> Option<usize> {
    let dst = out.get_mut(..ED25519_KEY_BLOB_LEN)?;
    let w = encode_string(ED25519, dst)?;
    Some(w + encode_string(key, &mut dst[w..])?)
}

/// Encode `string "ssh-ed25519" || string <signature>` — the signature
/// blob of a signed `publickey` request (RFC4252 §7).
pub fn ed25519_signature_blob(
    signature: &[u8; ED25519_SIGNATURE_LEN],
    out: &mut [u8],
) -> Option<usize> {
    let dst = out.get_mut(..ED25519_SIG_BLOB_LEN)?;
    let w = encode_string(ED25519, dst)?;
    Some(w + encode_string(signature, &mut dst[w..])?)
}

/// `string algorithm || string <N bytes>`, nothing else — the shared
/// shape of the key and signature blobs.
fn parse_ed25519_blob<const N: usize>(blob: &[u8]) -> Result<[u8; N], KeyError> {
    let mut r = Reader { buf: blob, pos: 0 };
    let alg_len = r.u32().map_err(|_| KeyError::Truncated)?;
    let alg_len = usize::try_from(alg_len).map_err(|_| KeyError::Truncated)?;
    let alg = r.take(alg_len).map_err(|_| KeyError::Truncated)?;
    if alg != ED25519 {
        return Err(KeyError::WrongAlgorithm);
    }
    let len = r.u32().map_err(|_| KeyError::Truncated)?;
    let len = usize::try_from(len).map_err(|_| KeyError::Truncated)?;
    if len != N {
        return Err(KeyError::BadLength);
    }
    let body = r.take(N).map_err(|_| KeyError::Truncated)?;
    if r.pos != blob.len() {
        return Err(KeyError::TrailingGarbage);
    }
    <[u8; N]>::try_from(body).map_err(|_| KeyError::BadLength)
}

/// Parse a `string "ssh-ed25519" || string <32 bytes>` public-key blob
/// back into the raw key — the fail-closed inverse of
/// [`ed25519_key_blob`]. Refuses a wrong algorithm, a wrong key length,
/// trailing bytes and every truncation.
pub fn parse_ed25519_key_blob(blob: &[u8]) -> Result<[u8; ED25519_KEY_LEN], KeyError> {
    parse_ed25519_blob(blob)
}

/// Parse a signature blob back into its raw 64-byte signature — the
/// fail-closed inverse of [`ed25519_signature_blob`].
pub fn parse_ed25519_signature_blob(blob: &[u8]) -> Result<[u8; ED25519_SIGNATURE_LEN], KeyError> {
    parse_ed25519_blob(blob)
}

/// The `SSH_MSG_USERAUTH_REQUEST` payload for the `publickey` method
/// (RFC4252 §7):
///
/// ```text
/// byte      SSH_MSG_USERAUTH_REQUEST (50)
/// string    user name                 ("git")
/// string    service name              ("ssh-connection")
/// string    method name               ("publickey")
/// boolean   TRUE if a signature follows
/// string    public key algorithm      ("ssh-ed25519")
/// string    public key blob           (string "ssh-ed25519" || string key)
/// string    signature                 (only when TRUE)
/// ```
///
/// With `signature = None` this is the **probe** — "would you accept
/// this key?" — which is *not* what the signature covers: RFC4252 §7
/// signs the signed form (boolean TRUE) with the signature field
/// omitted, i.e. [`userauth_signed_prefix`] prefixed by the session
/// identifier ([`userauth_signed_data`]). Both the key blob and (when
/// present) the signature blob are parsed back first, so a malformed
/// blob can never reach the wire with a `TRUE` boolean claiming it is
/// signed.
pub fn userauth_publickey_payload(
    user: &[u8],
    key_blob: &[u8],
    signature: Option<&[u8]>,
    out: &mut [u8],
) -> Option<usize> {
    let signed = signature.is_some();
    userauth_publickey_payload_inner(user, key_blob, signed, signature, out)
}

/// The `SSH_MSG_USERAUTH_REQUEST` prefix a `publickey` **signature**
/// covers (RFC4252 §7): the request with `boolean TRUE` and **no**
/// signature field — i.e. the signed request as sent, minus its last
/// `string signature`. Signing the probe (boolean FALSE) is a common
/// mistake and no server accepts it.
pub fn userauth_signed_prefix(user: &[u8], key_blob: &[u8], out: &mut [u8]) -> Option<usize> {
    userauth_publickey_payload_inner(user, key_blob, true, None, out)
}

fn userauth_publickey_payload_inner(
    user: &[u8],
    key_blob: &[u8],
    signed: bool,
    signature: Option<&[u8]>,
    out: &mut [u8],
) -> Option<usize> {
    if user.is_empty() {
        return None;
    }
    // Fail closed on anything but a well-formed ed25519 key blob.
    let _key = parse_ed25519_key_blob(key_blob).ok()?;
    if signature.is_some() && !signed {
        return None;
    }
    let sig_len = match signature {
        Some(sig) => {
            let _raw = parse_ed25519_signature_blob(sig).ok()?;
            Some(sig.len())
        }
        None => None,
    };
    let mut total = 1usize;
    total = total.checked_add(4)?.checked_add(user.len())?;
    total = total.checked_add(4)?.checked_add(AUTH_SERVICE.len())?;
    total = total
        .checked_add(4)?
        .checked_add(AUTH_METHOD_PUBLICKEY.len())?;
    total = total
        .checked_add(1)?
        .checked_add(4)?
        .checked_add(ED25519.len())?;
    total = total.checked_add(4)?.checked_add(key_blob.len())?;
    if let Some(n) = sig_len {
        total = total.checked_add(4)?.checked_add(n)?;
    }
    let dst = out.get_mut(..total)?;
    let mut w = 0usize;
    dst[w] = SSH_MSG_USERAUTH_REQUEST;
    w += 1;
    w += encode_string(user, &mut dst[w..])?;
    w += encode_string(AUTH_SERVICE, &mut dst[w..])?;
    w += encode_string(AUTH_METHOD_PUBLICKEY, &mut dst[w..])?;
    dst[w] = u8::from(signed);
    w += 1;
    w += encode_string(ED25519, &mut dst[w..])?;
    w += encode_string(key_blob, &mut dst[w..])?;
    if let Some(sig) = signature {
        w += encode_string(sig, &mut dst[w..])?;
    }
    // `w == total` by construction (the precheck above sized the
    // buffer); return what was actually written.
    Some(w)
}

/// The data an ed25519 `publickey` signature covers (RFC4252 §7 with
/// RFC4253 §8's "session identifier"): `string session_id ‖ request`,
/// where `request` is the signed `SSH_MSG_USERAUTH_REQUEST` payload **without**
/// its signature field — [`userauth_signed_prefix`], *not* the probe
/// (the probe carries boolean FALSE, the signed form TRUE).
///
/// RFC4252 §7 spells the first field **`string session identifier`**,
/// and a `string` is `uint32 length ‖ bytes` (RFC4251 §5) — so the
/// session id is *length-prefixed*, not raw. OpenSSH assembles the
/// same bytes with `sshbuf_put_stringb(b, ssh->kex->session_id)` in
/// `sign_and_send_pubkey` (`sshconnect2.c`). Writing the raw 32 bytes
/// here made our own client and server agree with each other (both
/// sides shared the bug, so `cargo xtask smoke-ssh` stayed green)
/// while every third-party peer rejected the signature — the
/// 2026-11-22 live-hardware failure where Debian's OpenSSH got
/// `Permission denied (publickey)` against our sshd.
pub fn userauth_signed_data(
    session_id: &[u8],
    request_without_signature: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    if session_id.is_empty() || request_without_signature.is_empty() {
        return None;
    }
    let total = 4usize
        .checked_add(session_id.len())?
        .checked_add(request_without_signature.len())?;
    let slen = u32::try_from(session_id.len()).ok()?;
    let dst = out.get_mut(..total)?;
    dst[..4].copy_from_slice(&slen.to_be_bytes());
    dst[4..4 + session_id.len()].copy_from_slice(session_id);
    dst[4 + session_id.len()..].copy_from_slice(request_without_signature);
    Some(total)
}

/// A parsed `SSH_MSG_USERAUTH_PK_OK` (RFC4252 §7): the server will
/// accept this key, send the signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PkOk<'a> {
    /// `public key algorithm` — validated to be [`ED25519`].
    pub algorithm: &'a [u8],
    /// The echo of our key blob — the caller must check it is **its**
    /// blob (a server answering about another key is a protocol error).
    pub key_blob: &'a [u8],
}

/// Parse a complete `SSH_MSG_USERAUTH_PK_OK` **payload** (message byte
/// included). Refuses a wrong algorithm, a key blob that is not a
/// well-formed ed25519 key, and trailing bytes.
pub fn parse_userauth_pk_ok(payload: &[u8]) -> Result<PkOk<'_>, UserAuthError> {
    let read = |e: KexError| match e {
        KexError::Truncated => UserAuthError::Truncated,
        _ => UserAuthError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_USERAUTH_PK_OK {
        return Err(UserAuthError::WrongMessage);
    }
    let alg_len = r.u32().map_err(read)?;
    let alg_len = usize::try_from(alg_len).map_err(|_| UserAuthError::Truncated)?;
    let algorithm = r.take(alg_len).map_err(read)?;
    if algorithm != ED25519 {
        return Err(UserAuthError::WrongAlgorithm);
    }
    let blob_len = r.u32().map_err(read)?;
    let blob_len = usize::try_from(blob_len).map_err(|_| UserAuthError::Truncated)?;
    let key_blob = r.take(blob_len).map_err(read)?;
    if parse_ed25519_key_blob(key_blob).is_err() {
        return Err(UserAuthError::BadKey);
    }
    if r.pos != payload.len() {
        return Err(UserAuthError::TrailingGarbage);
    }
    Ok(PkOk {
        algorithm,
        key_blob,
    })
}

/// Parse a `SSH_MSG_USERAUTH_SUCCESS` payload: the message byte and
/// nothing else (RFC4252 §5.3).
pub fn parse_userauth_success(payload: &[u8]) -> Result<(), UserAuthError> {
    match payload.first() {
        Some(&SSH_MSG_USERAUTH_SUCCESS) if payload.len() == 1 => Ok(()),
        Some(&SSH_MSG_USERAUTH_SUCCESS) => Err(UserAuthError::TrailingGarbage),
        Some(_) => Err(UserAuthError::WrongMessage),
        None => Err(UserAuthError::Truncated),
    }
}

/// Build an `SSH_MSG_USERAUTH_BANNER` **payload** (RFC4252 §5.4): the
/// message byte, an empty language string and the message string.
/// `None` when the message does not fit `out`.
pub fn userauth_banner_payload(message: &[u8], out: &mut [u8]) -> Option<usize> {
    let msg_len = u32::try_from(message.len()).ok()?;
    let total = 1usize
        .checked_add(4)?
        .checked_add(4)?
        .checked_add(message.len())?;
    let buf = out.get_mut(..total)?;
    buf[0] = SSH_MSG_USERAUTH_BANNER;
    buf[1..5].copy_from_slice(&0u32.to_be_bytes()); // language tag: ""
    buf[5..9].copy_from_slice(&msg_len.to_be_bytes());
    buf[9..].copy_from_slice(message);
    Some(total)
}

/// A parsed `SSH_MSG_USERAUTH_BANNER` (RFC4252 §5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAuthBanner<'a> {
    /// Free text the server wants shown to the user (US-ASCII or
    /// UTF-8 per the RFC) — sanitize before printing it anywhere.
    pub message: &'a [u8],
    /// RFC3066 language tag (may be empty).
    pub language: &'a [u8],
}

/// Parse a complete `SSH_MSG_USERAUTH_BANNER` **payload** (message byte
/// included). A server may send it at any point during authentication,
/// so the client tolerates (bounded) banners before the real answer.
pub fn parse_userauth_banner(payload: &[u8]) -> Result<UserAuthBanner<'_>, UserAuthError> {
    let read = |_: KexError| UserAuthError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_USERAUTH_BANNER {
        return Err(UserAuthError::WrongMessage);
    }
    let msg_len = r.u32().map_err(read)?;
    let msg_len = usize::try_from(msg_len).map_err(|_| UserAuthError::Truncated)?;
    let message = r.take(msg_len).map_err(read)?;
    let lang_len = r.u32().map_err(read)?;
    let lang_len = usize::try_from(lang_len).map_err(|_| UserAuthError::Truncated)?;
    let language = r.take(lang_len).map_err(read)?;
    if r.pos != payload.len() {
        return Err(UserAuthError::TrailingGarbage);
    }
    Ok(UserAuthBanner { message, language })
}

/// Parse a 32-byte ed25519 seed from hex text (the manual `ssh-auth`
/// path, docs §B.4 row S3): ASCII whitespace at both ends is trimmed
/// (a file written by an editor usually ends in a newline), the rest
/// must be exactly 64 hex digits. Both cases are accepted. The seed is
/// secret key material — callers must never log it.
pub fn parse_seed_hex(text: &[u8], out: &mut [u8; ED25519_KEY_LEN]) -> Result<(), KeyError> {
    let is_space = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let start = text.iter().take_while(|b| is_space(b)).count();
    let end = text
        .iter()
        .rposition(|b| !is_space(b))
        .map_or(start, |i| i + 1);
    let hex = text.get(start..end).unwrap_or(&[]);
    if hex.len() != ED25519_KEY_LEN * 2 {
        return Err(KeyError::BadHexLength);
    }
    let digit = |b: u8| -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    };
    let (pairs, _odd) = hex.as_chunks::<2>();
    for (pair, slot) in pairs.iter().zip(out.iter_mut()) {
        let hi = digit(pair[0]).ok_or(KeyError::NotHex)?;
        let lo = digit(pair[1]).ok_or(KeyError::NotHex)?;
        *slot = (hi << 4) | lo;
    }
    Ok(())
}

/// Standard-alphabet base64 (`A–Z a–z 0–9 + /`), with `=` padding only
/// when `padded` — SSH fingerprints are unpadded, `authorized_keys`
/// bodies are padded. No line breaks (RFC4648 §3.2/§3.3). `None` when
/// the output does not fit `out`.
pub fn base64_encode(input: &[u8], padded: bool, out: &mut [u8]) -> Option<usize> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut groups = input.len() / 3;
    if !input.len().is_multiple_of(3) {
        groups = groups.checked_add(1)?;
    }
    let mut total = groups.checked_mul(4)?;
    if !padded && !input.len().is_multiple_of(3) {
        // MySQL/base64 "unpadded": drop the 1–2 `=` the last group adds.
        total = total.checked_sub(3 - input.len() % 3)?;
    }
    let dst = out.get_mut(..total)?;
    let mut w = 0usize;
    for chunk in input.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied();
        let b2 = chunk.get(2).copied();
        let triple =
            (u32::from(b0) << 16) | (u32::from(b1.unwrap_or(0)) << 8) | u32::from(b2.unwrap_or(0));
        let idx = |shift: u32| -> Option<u8> {
            let i = ((triple >> shift) & 0x3f) as usize;
            ALPHABET.get(i).copied()
        };
        let mut quartet = [0u8; 4];
        quartet[0] = idx(18)?;
        quartet[1] = idx(12)?;
        quartet[2] = match (b1, padded) {
            (Some(_), _) => idx(6)?,
            (None, true) => b'=',
            (None, false) => 0, // never copied: `n` stops short
        };
        quartet[3] = match (b2, padded) {
            (Some(_), _) => idx(0)?,
            (None, true) => b'=',
            (None, false) => 0, // never copied
        };
        // Unpadded output stops after the characters that carry data.
        let n = if padded { 4 } else { chunk.len() + 1 };
        dst.get_mut(w..w.checked_add(n)?)?
            .copy_from_slice(quartet.get(..n)?);
        w += n;
    }
    Some(w)
}

/// Length of an SSH SHA-256 fingerprint: `"SHA256:"` + unpadded base64
/// of a 32-byte digest (43 characters).
pub const FINGERPRINT_LEN: usize = 7 + 43;

/// Write the OpenSSH SHA-256 fingerprint of a key blob
/// (`SHA256:` + unpadded base64 of SHA-256(blob)) — the string
/// `ssh-keygen -lf` prints and GitHub's fingerprints page lists. The
/// digest is computed by the caller (audited SHA-256 in the kernel);
/// this is the display encoding only.
pub fn write_fingerprint(digest: &[u8; 32], out: &mut [u8]) -> Option<usize> {
    let dst = out.get_mut(..FINGERPRINT_LEN)?;
    dst.get_mut(..7)?.copy_from_slice(b"SHA256:");
    let n = base64_encode(digest, false, dst.get_mut(7..)?)?;
    Some(7 + n)
}

/// Why key derivation refused its inputs (RFC4253 §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfError {
    /// The letter is not `'A'..='F'`.
    BadLetter,
    /// `out` is empty or longer than [`KDF_MAX_OUTPUT`].
    BadLength,
    /// An input (`k`, `h`, `session_id`) exceeds the bound the fixed
    /// input buffer holds — never an allocation.
    InputTooLong,
}

/// Hard cap on one derivation's output: four SHA-256 blocks, well
/// above the 32 bytes `aes*-ctr` + `hmac-sha2-256` ever needs. It
/// exists so [`kdf`]'s input buffer is a fixed size.
pub const KDF_MAX_OUTPUT: usize = 128;

/// RFC4253 §7.2 key derivation, `HASH` supplied by the caller (the
/// kernel passes audited SHA-256 — this crate has no primitive):
///
/// ```text
/// K1 = HASH(mpint(K) || H || X || session_id)     (X = the letter)
/// Kn = HASH(mpint(K) || H || K1 || … || Kn-1)
/// key = K1 || K2 || … , truncated to out.len()
/// ```
///
/// Encodings follow the RFC's parenthetical exactly and match
/// OpenSSH's `derive_key` byte for byte: `K` as `mpint`
/// ([`encode_mpint`]), `H` raw, the letter as a single raw byte, and
/// `session_id` raw (for the first key set it *is* `H`, already
/// hash-sized — no length prefix anywhere but `mpint(K)`).
pub fn kdf(
    hash: impl Fn(&[u8]) -> [u8; 32],
    k: &[u8],
    h: &[u8],
    letter: u8,
    session_id: &[u8],
    out: &mut [u8],
) -> Result<(), KdfError> {
    if !(b'A'..=b'F').contains(&letter) {
        return Err(KdfError::BadLetter);
    }
    if out.is_empty() || out.len() > KDF_MAX_OUTPUT {
        return Err(KdfError::BadLength);
    }
    // Fixed input-buffer bounds: mpint(k) ≤ 4+1+64, plus h, letter,
    // session_id (or the previous output) — see the buffer below.
    if k.len() > 64 || h.len() > 64 || session_id.len() > 64 {
        return Err(KdfError::InputTooLong);
    }
    // mpint(K) ≤ 4 + 1 + 64 = 69; chained input ≤ 69 + 64 + 128 = 261.
    let mut input = [0u8; 264];
    let mlen = encode_mpint(k, &mut input).ok_or(KdfError::InputTooLong)?;
    input[mlen..mlen + h.len()].copy_from_slice(h);
    let mut n = mlen + h.len();
    input[n] = letter;
    n += 1;
    input[n..n + session_id.len()].copy_from_slice(session_id);
    n += session_id.len();
    let first = hash(&input[..n]);
    let take = out.len().min(32);
    out[..take].copy_from_slice(&first[..take]);
    let mut have = take;
    while have < out.len() {
        let mlen = encode_mpint(k, &mut input).ok_or(KdfError::InputTooLong)?;
        input[mlen..mlen + h.len()].copy_from_slice(h);
        let n = mlen + h.len();
        input[n..n + have].copy_from_slice(&out[..have]);
        let block = hash(&input[..n + have]);
        let take = (out.len() - have).min(32);
        out[have..have + take].copy_from_slice(&block[..take]);
        have += take;
    }
    Ok(())
}

/// Equality for MAC tags with no early exit on the first differing
/// byte (the *length* is public — it is checked up front). A single
/// flipped bit anywhere makes this `false`, which is exactly the
/// fail-closed gate the encrypted phase needs.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Directional packet protection for the encrypted phase (RFC4253
/// §6.3/§6.4). The kernel implements it over audited primitives (the
/// continuous AES-CTR keystream + HMAC-SHA256 keys from the RFC4253
/// §7.2 KDF); the host tests implement it with the same crates at a
/// fixed key/IV. This trait is protocol glue — `ssh-wire` itself
/// contains no primitive.
pub trait PacketProtector {
    /// Cipher block size; packets align to `max(block, 8)` (16 for
    /// every `aes*-ctr` we negotiate).
    fn block_size(&self) -> usize;
    /// Decrypt `buf` in place — AES-CTR is a stream cipher, so this is
    /// the same keystream application as `seal`, applied over exactly
    /// the ciphertext region, never the trailing MAC tag. The keystream
    /// is continuous across packets (RFC4253 §6.3: IVs pass from one
    /// packet to the next).
    fn open(&mut self, buf: &mut [u8]);
    /// Encrypt `buf` in place (the framed packet, plaintext order).
    fn seal(&mut self, buf: &mut [u8]);
    /// `MAC(key, seq_be32 || unencrypted_packet)` (RFC4253 §6.4).
    fn tag(&mut self, seq: u32, packet: &[u8]) -> [u8; TAG_LEN];
}

/// Build the full encrypted-phase wire packet: frame `payload`
/// ([`encode_packet`], random padding from `fill_pad`), MAC the
/// **plaintext** with `seq`, encrypt in place, append the tag in the
/// clear (RFC4253 §6.4). `None` when it does not fit `out`.
pub fn seal_packet<P: PacketProtector>(
    payload: &[u8],
    fill_pad: impl FnMut(&mut [u8]),
    p: &mut P,
    seq: u32,
    out: &mut [u8],
) -> Option<usize> {
    let total = encode_packet(payload, p.block_size(), fill_pad, out)?;
    // The MAC covers the unencrypted packet — compute it before the
    // keystream touches a byte, append it after.
    let tag = p.tag(seq, &out[..total]);
    p.seal(&mut out[..total]);
    let wire = out.get_mut(total..total + TAG_LEN)?;
    wire.copy_from_slice(&tag);
    Some(total + TAG_LEN)
}

/// Why the encrypted receiver refused a packet. Fail-closed: every
/// variant means the connection is unusable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The (decrypted) packet structure is illegal — bounds checked
    /// before any wait.
    Packet(PacketError),
    /// The MAC tag does not verify: tampering or a desynced stream.
    MacMismatch,
    /// The fixed receive buffer is full before the packet completed
    /// (or the declared packet plus tag could never fit it).
    Full,
    /// The declared `4 + packet_length + TAG_LEN` exceeds the fixed
    /// receive buffer — a hostile length, refused from the header
    /// alone, never waited on.
    TooLarge,
}

/// Incremental receiver for the encrypted phase. smoltcp hands over
/// arbitrary read splits and the packet length itself is ciphertext,
/// so bytes are decrypted exactly up to the ciphertext/MAC boundary as
/// they arrive (the boundary becomes known after the first four
/// decrypted bytes, RFC4253 §6.3's "decrypt the length after the first
/// block"), the tag is verified over the plaintext with the direction's
/// sequence number, and only then does the payload surface. The buffer
/// is fixed — a hostile declared length fails by bounds, never by
/// allocation.
#[derive(Debug)]
pub struct EncryptedRx<'a> {
    buf: &'a mut [u8],
    /// Raw bytes received so far.
    got: usize,
    /// Start of the packet being assembled (bytes before it were
    /// already consumed).
    base: usize,
    /// Bytes of `[base..]` already decrypted (the keystream frontier).
    frontier: usize,
    /// `4 + packet_length` of the current packet, once its header has
    /// been decrypted and validated.
    cipher_len: Option<usize>,
    /// Shift to apply before the next packet (set by [`Self::next`],
    /// applied by [`Self::consume`] — belt and braces, so a skipped
    /// `consume` cannot desync the stream).
    pending: Option<usize>,
}

impl<'a> EncryptedRx<'a> {
    /// `initial` = bytes already in `buf` (ciphertext pipelined behind
    /// the plaintext `SSH_MSG_NEWKEYS`). More than the buffer holds is
    /// clamped — impossible from a correct caller, and dropping bytes
    /// fails the MAC later rather than panicking.
    pub fn new(buf: &'a mut [u8], initial: usize) -> Self {
        Self {
            got: initial.min(buf.len()),
            base: 0,
            frontier: 0,
            cipher_len: None,
            pending: None,
            buf,
        }
    }

    /// Free space for the next transport read.
    pub fn spare(&mut self) -> Result<&mut [u8], OpenError> {
        if self.got >= self.buf.len() {
            return Err(OpenError::Full);
        }
        Ok(&mut self.buf[self.got..])
    }

    /// Record `n` freshly received bytes (from a read into
    /// [`Self::spare`]).
    pub fn commit(&mut self, n: usize) {
        // `n` cannot exceed the spare slice; the clamp is belt and
        // braces against a caller bug, never a panic.
        self.got = (self.got + n).min(self.buf.len());
    }

    /// Copy already-received bytes into the buffer (the transport-read
    /// step for callers that hold the bytes up front — the kernel
    /// reads straight into [`Self::spare`] instead). `Err(Full)` when
    /// they do not fit: the buffer never grows, a hostile stream is
    /// refused rather than allocated.
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), OpenError> {
        let end = self.got.checked_add(bytes.len()).ok_or(OpenError::Full)?;
        if end > self.buf.len() {
            return Err(OpenError::Full);
        }
        self.buf[self.got..end].copy_from_slice(bytes);
        self.got = end;
        Ok(())
    }

    /// All bytes received so far — the payload range from
    /// [`Self::next`] indexes into this.
    pub fn bytes(&self) -> &[u8] {
        self.buf
    }

    /// Drop the packet [`Self::next`] just returned (payload + tag).
    /// [`Self::next`] also applies a forgotten pending shift itself,
    /// so the stream cannot desync either way.
    pub fn consume(&mut self) {
        self.apply_pending();
    }

    fn apply_pending(&mut self) {
        let Some(shift) = self.pending.take() else {
            return;
        };
        let shift = shift.min(self.got);
        self.buf.copy_within(shift..self.got, 0);
        self.got -= shift;
        self.base = 0;
        self.frontier = 0;
        self.cipher_len = None;
    }

    /// Decrypt/verify/decode the packet at the front; on success
    /// returns its payload's byte range within [`Self::bytes`]
    /// (read it, then call [`Self::consume`]). `Ok(None)` = need more
    /// bytes. `seq` is this direction's packet sequence number —
    /// per-direction, never reset (RFC4253 §6.4).
    pub fn next<P: PacketProtector>(
        &mut self,
        p: &mut P,
        seq: u32,
    ) -> Result<Option<(usize, usize)>, OpenError> {
        self.apply_pending();
        let block = p.block_size();
        loop {
            // 1. Decrypt what is knowable: up to the ciphertext
            //    boundary once the header is known, otherwise only
            //    the first four bytes (the length is ciphertext).
            let target = match self.cipher_len {
                Some(cl) => self.base + cl,
                None => self.base + 4,
            }
            .min(self.got);
            if self.frontier < target {
                p.open(&mut self.buf[self.frontier..target]);
                self.frontier = target;
            }
            // 2. Four bytes in: learn (and bound) the packet length.
            if self.cipher_len.is_none() && self.got - self.base >= 4 {
                let head = &self.buf[self.base..self.base + 4];
                let cl = match packet_total(head, block).map_err(OpenError::Packet)? {
                    Some(cl) => cl,
                    // Fewer than four bytes — cannot happen here;
                    // treat as "need more" rather than spin.
                    None => return Ok(None),
                };
                if self.base + cl + TAG_LEN > self.buf.len() {
                    return Err(OpenError::TooLarge);
                }
                self.cipher_len = Some(cl);
                continue; // decrypt up to the new boundary
            }
            // 3. Complete ciphertext + tag in the buffer?
            if let Some(cl) = self.cipher_len {
                if self.got < self.base + cl + TAG_LEN {
                    if self.got >= self.buf.len() {
                        return Err(OpenError::Full);
                    }
                    return Ok(None);
                }
                let plain = &self.buf[self.base..self.base + cl];
                let tag = p.tag(seq, plain);
                let wire_tag = &self.buf[self.base + cl..self.base + cl + TAG_LEN];
                if !ct_eq(&tag, wire_tag) {
                    return Err(OpenError::MacMismatch);
                }
                let payload = match decode_packet_block(plain, block) {
                    PacketStep::Done { consumed, payload } if consumed == cl => payload,
                    // Defensive: same header, same block — but a
                    // malicious `padding_length` still dies here.
                    PacketStep::Done { .. } => {
                        return Err(OpenError::Packet(PacketError::BadPadding));
                    }
                    PacketStep::Incomplete => return Err(OpenError::Packet(PacketError::TooSmall)),
                    PacketStep::Failed(e) => return Err(OpenError::Packet(e)),
                };
                let start = self.base + 5;
                let end = start + (payload.len());
                self.pending = Some(cl + TAG_LEN);
                return Ok(Some((start, end)));
            }
            // Header still short of four bytes.
            if self.got >= self.buf.len() {
                return Err(OpenError::Full);
            }
            return Ok(None);
        }
    }
}

// ---- S5: server side (KEX responder, user auth, session channels) ----
//
// The mirror image of the client glue above. Same rules: pure wire
// layout, caller-provided buffers, no primitive and no allocation. Every
// parser is fail-closed — the kernel turns an `Err` into "drop the
// connection with a bounded reason", never into a retry or a guess.

/// The server's cipher list: exactly the one cipher the sshd
/// implements (docs/git-ssh-deps.md §B.4 row S5). Our client lists
/// `aes128-ctr` first, so the intersection stays there.
pub const SERVER_ENCRYPTION_ALGORITHMS: &str = "aes128-ctr";

/// The ten name-lists the server sends (RFC4253 §7.1 wire order).
/// `ext-info-s` is deliberately absent: we never send EXT_INFO.
pub const SERVER_LISTS: [&str; 10] = [
    SERVER_KEX_ALGORITHMS,
    HOST_KEY_ALGORITHMS,
    SERVER_ENCRYPTION_ALGORITHMS,
    SERVER_ENCRYPTION_ALGORITHMS,
    MAC_ALGORITHMS,
    MAC_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
    COMPRESSION_ALGORITHMS,
    "",
    "",
];

/// The kex list a server sends. As a responder the server must not
/// advertise the client-only `ext-info-c` signal.
pub const SERVER_KEX_ALGORITHMS: &str = "curve25519-sha256";

/// Encode any ten name-lists as one framed `SSH_MSG_KEXINIT` (the two
/// public wrappers below pick the client's or the server's fixed set).
fn encode_kexinit_lists(lists: [&str; 10], cookie: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    let payload_length = 1 + 16 + 10 * 4 + lists.iter().map(|l| l.len()).sum::<usize>() + 1 + 4;
    let unpadded = 4 + 1 + payload_length;
    let mut padding = (BLOCK_SIZE - unpadded % BLOCK_SIZE) % BLOCK_SIZE;
    if padding < MIN_PADDING {
        padding += BLOCK_SIZE;
    }
    let packet_length = 1 + payload_length + padding;
    let total = 4 + packet_length;
    if total > out.len() || total > KEXINIT_WIRE_MAX {
        return None;
    }
    let dst = out.get_mut(..total)?;
    let mut w = 0usize;
    dst[w..w + 4].copy_from_slice(&u32::try_from(packet_length).ok()?.to_be_bytes());
    w += 4;
    dst[w] = u8::try_from(padding).ok()?;
    w += 1;
    dst[w] = SSH_MSG_KEXINIT;
    w += 1;
    dst[w..w + 16].copy_from_slice(cookie);
    w += 16;
    for list in lists {
        dst[w..w + 4].copy_from_slice(&u32::try_from(list.len()).ok()?.to_be_bytes());
        w += 4;
        dst[w..w + list.len()].copy_from_slice(list.as_bytes());
        w += list.len();
    }
    dst[w] = 0; // first_kex_packet_follows = false
    w += 1;
    dst[w..w + 4].copy_from_slice(&0u32.to_be_bytes()); // reserved = 0
    for byte in dst[w..].iter_mut() {
        *byte = 0;
    }
    Some(total)
}

/// Encode the **server's** `SSH_MSG_KEXINIT` (S5) as a ready-to-send
/// plaintext packet. Same framing rules as [`encode_kexinit`].
pub fn encode_kexinit_server(cookie: &[u8; 16], out: &mut [u8]) -> Option<usize> {
    encode_kexinit_lists(SERVER_LISTS, cookie, out)
}

/// Intersect a **client's** KEXINIT with the server's fixed lists —
/// the mirror of [`intersect`]. RFC4253 §7.1 still gives the client's
/// ordering the choice; the server's lists are single-entry, so this
/// is "does the client offer what we implement".
pub fn intersect_as_server(client: &KexInit<'_>) -> Negotiated {
    // The server's lists are single-entry, so the negotiated value is
    // always *our* static name (never a string borrowed from the
    // client's packet) — `Negotiated`'s `'static` fields stay honest.
    let has =
        |list: &[u8], ours: &'static str| namelist_contains(list, ours.as_bytes()).then_some(ours);
    Negotiated {
        kex: has(client.kex_algorithms, SERVER_KEX_ALGORITHMS),
        host_key: has(client.server_host_key_algorithms, HOST_KEY_ALGORITHMS),
        enc_c2s: has(
            client.encryption_algorithms_c2s,
            SERVER_ENCRYPTION_ALGORITHMS,
        ),
        enc_s2c: has(
            client.encryption_algorithms_s2c,
            SERVER_ENCRYPTION_ALGORITHMS,
        ),
        mac_c2s: has(client.mac_algorithms_c2s, MAC_ALGORITHMS),
        mac_s2c: has(client.mac_algorithms_s2c, MAC_ALGORITHMS),
        comp_c2s: has(client.compression_algorithms_c2s, COMPRESSION_ALGORITHMS),
        comp_s2c: has(client.compression_algorithms_s2c, COMPRESSION_ALGORITHMS),
    }
}

/// Parse a `SSH_MSG_KEXDH_INIT` payload (RFC8731 §3): message byte +
/// `string` of exactly 32 X25519 bytes, not all-zero.
pub fn parse_kexdh_init(payload: &[u8]) -> Result<[u8; ED25519_KEY_LEN], KexDhError> {
    let read = |_: KexError| KexDhError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_KEXDH_INIT {
        return Err(KexDhError::WrongMessage);
    }
    let len = r.u32().map_err(read)?;
    if len != 32 {
        return Err(KexDhError::BadPublicKey);
    }
    let e = r.take(32).map_err(read)?;
    if e.iter().all(|&b| b == 0) {
        return Err(KexDhError::ZeroPublicKey);
    }
    if r.pos != payload.len() {
        return Err(KexDhError::TrailingGarbage);
    }
    <[u8; 32]>::try_from(e).map_err(|_| KexDhError::BadPublicKey)
}

/// Encode a `SSH_MSG_KEXDH_REPLY` payload (RFC4253 §8 / RFC8731 §3):
/// `K_S`, the server's 32-byte ephemeral value `f`, and the ed25519
/// signature blob over the exchange hash. Both blobs are re-validated
/// first, so a malformed key can never be signed for or sent.
pub fn kexdh_reply_payload(
    host_key_blob: &[u8],
    f: &[u8; 32],
    signature_blob: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let _ = parse_ed25519_key_blob(host_key_blob).ok()?;
    let _ = parse_ed25519_signature_blob(signature_blob).ok()?;
    let total = 1usize
        .checked_add(4)?
        .checked_add(host_key_blob.len())?
        .checked_add(4)?
        .checked_add(32)?
        .checked_add(4)?
        .checked_add(signature_blob.len())?;
    let dst = out.get_mut(..total)?;
    let mut w = 0usize;
    dst[w] = SSH_MSG_KEXDH_REPLY;
    w += 1;
    w += encode_string(host_key_blob, &mut dst[w..])?;
    w += encode_string(f, &mut dst[w..])?;
    w += encode_string(signature_blob, &mut dst[w..])?;
    Some(w)
}

/// Parse a `SSH_MSG_SERVICE_REQUEST` payload, returning the service
/// name (the caller checks it is `"ssh-userauth"`).
pub fn parse_service_request(payload: &[u8]) -> Result<&[u8], ServiceError> {
    let read = |_: KexError| ServiceError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_SERVICE_REQUEST {
        return Err(ServiceError::WrongMessage);
    }
    let nlen = r.u32().map_err(read)?;
    let nlen = usize::try_from(nlen).map_err(|_| ServiceError::Truncated)?;
    let name = r.take(nlen).map_err(read)?;
    if r.pos != payload.len() {
        return Err(ServiceError::TrailingGarbage);
    }
    Ok(name)
}

/// Encode `SSH_MSG_SERVICE_ACCEPT` for `name` (RFC4253 §10).
pub fn service_accept_payload(name: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 1usize.checked_add(4)?.checked_add(name.len())?;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_SERVICE_ACCEPT;
    Some(1 + encode_string(name, &mut dst[1..])?)
}

/// A parsed `SSH_MSG_USERAUTH_REQUEST` (RFC4252 §5/§7). Slices point
/// into the caller's payload; nothing is copied. For methods other
/// than `publickey` the key/signature fields are empty and
/// `signed_prefix` is unused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserAuthRequest<'a> {
    pub user: &'a [u8],
    pub service: &'a [u8],
    pub method: &'a [u8],
    /// `TRUE` when a signature follows (publickey method).
    pub has_signature: bool,
    /// `ssh-ed25519` for a publickey request.
    pub algorithm: &'a [u8],
    /// The `string "ssh-ed25519" || string key` blob as sent.
    pub key_blob: &'a [u8],
    /// The signature blob as sent (empty when `has_signature` is false).
    pub signature: &'a [u8],
    /// The request payload **without** the signature field — the piece
    /// the client's signature covers, prefixed by the session id
    /// (RFC4252 §7). Includes the `TRUE` boolean.
    pub signed_prefix: &'a [u8],
}

/// Parse a complete `SSH_MSG_USERAUTH_REQUEST` **payload** (message
/// byte included). Only the `none` and `publickey` methods are
/// understood — anything else is refused, so an unsupported method
/// never reaches the auth decision.
pub fn parse_userauth_request(payload: &[u8]) -> Result<UserAuthRequest<'_>, UserAuthError> {
    let read = |e: KexError| match e {
        KexError::Truncated => UserAuthError::Truncated,
        _ => UserAuthError::Truncated,
    };
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_USERAUTH_REQUEST {
        return Err(UserAuthError::WrongMessage);
    }
    let ulen = r.u32().map_err(read)?;
    let ulen = usize::try_from(ulen).map_err(|_| UserAuthError::Truncated)?;
    let user = r.take(ulen).map_err(read)?;
    if user.is_empty() {
        return Err(UserAuthError::Truncated);
    }
    let slen = r.u32().map_err(read)?;
    let slen = usize::try_from(slen).map_err(|_| UserAuthError::Truncated)?;
    let service = r.take(slen).map_err(read)?;
    let mlen = r.u32().map_err(read)?;
    let mlen = usize::try_from(mlen).map_err(|_| UserAuthError::Truncated)?;
    let method = r.take(mlen).map_err(read)?;
    if method == b"none" {
        if r.pos != payload.len() {
            return Err(UserAuthError::TrailingGarbage);
        }
        return Ok(UserAuthRequest {
            user,
            service,
            method,
            has_signature: false,
            algorithm: &[],
            key_blob: &[],
            signature: &[],
            signed_prefix: payload,
        });
    }
    if method != AUTH_METHOD_PUBLICKEY {
        return Err(UserAuthError::UnsupportedMethod);
    }
    let has_signature = match r.u8().map_err(read)? {
        0 => false,
        1 => true,
        _ => return Err(UserAuthError::BadBoolean),
    };
    let alen = r.u32().map_err(read)?;
    let alen = usize::try_from(alen).map_err(|_| UserAuthError::Truncated)?;
    let algorithm = r.take(alen).map_err(read)?;
    if algorithm != ED25519 {
        return Err(UserAuthError::WrongAlgorithm);
    }
    let klen = r.u32().map_err(read)?;
    let klen = usize::try_from(klen).map_err(|_| UserAuthError::Truncated)?;
    let key_blob = r.take(klen).map_err(read)?;
    if parse_ed25519_key_blob(key_blob).is_err() {
        return Err(UserAuthError::BadKey);
    }
    if !has_signature {
        if r.pos != payload.len() {
            return Err(UserAuthError::TrailingGarbage);
        }
        return Ok(UserAuthRequest {
            user,
            service,
            method,
            has_signature,
            algorithm,
            key_blob,
            signature: &[],
            signed_prefix: payload,
        });
    }
    let signed_prefix = payload.get(..r.pos).ok_or(UserAuthError::Truncated)?;
    let siglen = r.u32().map_err(read)?;
    let siglen = usize::try_from(siglen).map_err(|_| UserAuthError::Truncated)?;
    let signature = r.take(siglen).map_err(read)?;
    if parse_ed25519_signature_blob(signature).is_err() {
        return Err(UserAuthError::BadSignature);
    }
    if r.pos != payload.len() {
        return Err(UserAuthError::TrailingGarbage);
    }
    Ok(UserAuthRequest {
        user,
        service,
        method,
        has_signature,
        algorithm,
        key_blob,
        signature,
        signed_prefix,
    })
}

/// Encode `SSH_MSG_USERAUTH_FAILURE` (RFC4252 §5.1 field order:
/// name-list then boolean).
pub fn userauth_failure_payload(
    methods: &[u8],
    partial_success: bool,
    out: &mut [u8],
) -> Option<usize> {
    validate_namelist(methods).ok()?;
    let total = 1usize
        .checked_add(4)?
        .checked_add(methods.len())?
        .checked_add(1)?;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_USERAUTH_FAILURE;
    let n = encode_string(methods, &mut dst[1..])?;
    dst[1 + n] = u8::from(partial_success);
    Some(total)
}

/// Encode `SSH_MSG_USERAUTH_SUCCESS` — a bare message byte.
pub fn userauth_success_payload(out: &mut [u8]) -> Option<usize> {
    *out.first_mut()? = SSH_MSG_USERAUTH_SUCCESS;
    Some(1)
}

/// Encode `SSH_MSG_USERAUTH_PK_OK` (RFC4252 §7): the algorithm and the
/// key blob echoed back, telling the client to send its signature.
pub fn userauth_pk_ok_payload(key_blob: &[u8], out: &mut [u8]) -> Option<usize> {
    let _ = parse_ed25519_key_blob(key_blob).ok()?;
    let total = 1usize
        .checked_add(4)?
        .checked_add(ED25519.len())?
        .checked_add(4)?
        .checked_add(key_blob.len())?;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_USERAUTH_PK_OK;
    let mut w = 1usize;
    w += encode_string(ED25519, &mut dst[w..])?;
    w += encode_string(key_blob, &mut dst[w..])?;
    Some(w)
}

/// Strict standard-alphabet base64 decoder (RFC4648 §4): `=` padding
/// required for a final group, ASCII whitespace at both ends ignored,
/// anything else refused. Used for `authorized_keys` bodies; `None`
/// when the output does not fit or the text is malformed.
pub fn base64_decode(text: &[u8], out: &mut [u8]) -> Option<usize> {
    fn value(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let is_space = |b: &u8| matches!(b, b' ' | b'\t' | b'\r' | b'\n');
    let start = text.iter().take_while(|b| is_space(b)).count();
    let end = text
        .iter()
        .rposition(|b| !is_space(b))
        .map_or(start, |i| i + 1);
    let text = text.get(start..end)?;
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut w = 0usize;
    for (i, group) in text.chunks(4).enumerate() {
        let last = i == text.len() / 4 - 1;
        let pad = group.iter().rev().take_while(|&&b| b == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut acc = 0u32;
        for (j, &b) in group.iter().enumerate() {
            let v = if b == b'=' {
                // Padding is only legal in the final group's last two
                // positions, and implies the omitted bytes are zero.
                if !last || j < 4 - pad {
                    return None;
                }
                0
            } else {
                value(b)?
            };
            acc = (acc << 6) | u32::from(v);
        }
        let n = 3 - pad;
        let bytes = acc.to_be_bytes();
        // `acc` holds 24 bits in the low three bytes.
        let src = &bytes[1..4];
        let dst = out.get_mut(w..w.checked_add(n)?)?;
        dst.copy_from_slice(&src[..n]);
        w += n;
    }
    Some(w)
}

/// Parse one `authorized_keys` line: `[whitespace] "ssh-ed25519" SP
/// <base64 blob> [comment]`. Blank lines and `#` comments are skipped,
/// other key types are skipped line by line, and the first valid
/// ed25519 line wins. Fail-closed: a malformed *ed25519* line is an
/// error, never silently skipped (a typo must not look like "no key").
pub fn parse_authorized_key(text: &[u8], out: &mut [u8; ED25519_KEY_LEN]) -> Result<(), KeyError> {
    let mut line_start = 0usize;
    while line_start < text.len() {
        let line_end = text[line_start..]
            .iter()
            .position(|&b| b == b'\n' || b == b'\r')
            .map_or(text.len(), |i| line_start + i);
        let mut line = text.get(line_start..line_end).unwrap_or(&[]);
        line_start = line_end;
        while line_start < text.len() && matches!(text[line_start], b'\n' | b'\r') {
            line_start += 1;
        }
        // Trim ASCII space/tab.
        let trim = |b: &u8| *b == b' ' || *b == b'\t';
        let s = line.iter().take_while(|b| trim(b)).count();
        let e = line.iter().rposition(|b| !trim(b)).map_or(s, |i| i + 1);
        line = line.get(s..e).unwrap_or(&[]);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        if let Some(rest) = line.strip_prefix(ED25519) {
            let Some(rest) = rest.strip_prefix(b" ") else {
                return Err(KeyError::WrongAlgorithm);
            };
            let rest = rest.trim_ascii_start();
            let body_len = rest
                .iter()
                .position(|&b| b == b' ' || b == b'\t')
                .unwrap_or(rest.len());
            let body = rest.get(..body_len).unwrap_or(&[]);
            if body.is_empty() {
                return Err(KeyError::Truncated);
            }
            // 51-byte blob → 68 base64 characters.
            let mut blob = [0u8; 96];
            let n = base64_decode(body, &mut blob).ok_or(KeyError::NotBase64)?;
            let key = parse_ed25519_key_blob(blob.get(..n).unwrap_or(&[]))?;
            *out = key;
            return Ok(());
        }
        // A different key type: not ours, skip the line.
    }
    Err(KeyError::Truncated)
}

// --- S5b: session channels (`ssh-connection`, RFC4254 §5/§6) ---

pub const SSH_MSG_CHANNEL_OPEN: u8 = 90;
pub const SSH_MSG_CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const SSH_MSG_CHANNEL_OPEN_FAILURE: u8 = 92;
pub const SSH_MSG_CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const SSH_MSG_CHANNEL_DATA: u8 = 94;
pub const SSH_MSG_CHANNEL_EXTENDED_DATA: u8 = 95;
pub const SSH_MSG_CHANNEL_EOF: u8 = 96;
pub const SSH_MSG_CHANNEL_CLOSE: u8 = 97;
pub const SSH_MSG_CHANNEL_REQUEST: u8 = 98;
pub const SSH_MSG_CHANNEL_SUCCESS: u8 = 99;
pub const SSH_MSG_CHANNEL_FAILURE: u8 = 100;

/// Bound on an `exec` command string the server will accept (the
/// internal handler is a toy; a real shell milestone grows this).
pub const EXEC_COMMAND_MAX: usize = 256;

/// Why a channel message was refused. Fail-closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
    /// Not the expected channel message type.
    WrongMessage,
    /// A field runs past the payload.
    Truncated,
    /// `want_reply` is not 0 or 1.
    BadBoolean,
    /// The channel type is not `"session"` (the only one we open).
    UnsupportedType,
    /// An `exec` request with an empty or over-long command.
    BadCommand,
    /// Bytes after the last field.
    TrailingGarbage,
}

/// A parsed `SSH_MSG_CHANNEL_OPEN` (RFC4254 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelOpen<'a> {
    pub channel_type: &'a [u8],
    pub sender_channel: u32,
    pub initial_window: u32,
    pub max_packet: u32,
}

/// Parse a complete `SSH_MSG_CHANNEL_OPEN` **payload**.
pub fn parse_channel_open(payload: &[u8]) -> Result<ChannelOpen<'_>, ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_CHANNEL_OPEN {
        return Err(ChannelError::WrongMessage);
    }
    let tlen = r.u32().map_err(read)?;
    let tlen = usize::try_from(tlen).map_err(|_| ChannelError::Truncated)?;
    let channel_type = r.take(tlen).map_err(read)?;
    let sender_channel = r.u32().map_err(read)?;
    let initial_window = r.u32().map_err(read)?;
    let max_packet = r.u32().map_err(read)?;
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok(ChannelOpen {
        channel_type,
        sender_channel,
        initial_window,
        max_packet,
    })
}

/// Encode `SSH_MSG_CHANNEL_OPEN` for a `session` channel.
pub fn channel_open_session_payload(
    sender_channel: u32,
    initial_window: u32,
    max_packet: u32,
    out: &mut [u8],
) -> Option<usize> {
    const TYPE: &[u8] = b"session";
    let total = 1usize + 4 + TYPE.len() + 12;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_CHANNEL_OPEN;
    let mut w = 1usize;
    w += encode_string(TYPE, &mut dst[w..])?;
    dst[w..w + 4].copy_from_slice(&sender_channel.to_be_bytes());
    dst[w + 4..w + 8].copy_from_slice(&initial_window.to_be_bytes());
    dst[w + 8..w + 12].copy_from_slice(&max_packet.to_be_bytes());
    Some(total)
}

/// A parsed `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` (RFC4254 §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelOpenConfirmation {
    pub recipient_channel: u32,
    pub sender_channel: u32,
    pub initial_window: u32,
    pub max_packet: u32,
}

/// Parse a complete `SSH_MSG_CHANNEL_OPEN_CONFIRMATION` **payload**.
pub fn parse_channel_open_confirmation(
    payload: &[u8],
) -> Result<ChannelOpenConfirmation, ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_CHANNEL_OPEN_CONFIRMATION {
        return Err(ChannelError::WrongMessage);
    }
    let recipient_channel = r.u32().map_err(read)?;
    let sender_channel = r.u32().map_err(read)?;
    let initial_window = r.u32().map_err(read)?;
    let max_packet = r.u32().map_err(read)?;
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok(ChannelOpenConfirmation {
        recipient_channel,
        sender_channel,
        initial_window,
        max_packet,
    })
}

/// Encode `SSH_MSG_CHANNEL_OPEN_CONFIRMATION`.
pub fn channel_open_confirmation_payload(
    recipient_channel: u32,
    sender_channel: u32,
    initial_window: u32,
    max_packet: u32,
    out: &mut [u8],
) -> Option<usize> {
    let dst = out.get_mut(..17)?;
    dst[0] = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
    dst[1..5].copy_from_slice(&recipient_channel.to_be_bytes());
    dst[5..9].copy_from_slice(&sender_channel.to_be_bytes());
    dst[9..13].copy_from_slice(&initial_window.to_be_bytes());
    dst[13..17].copy_from_slice(&max_packet.to_be_bytes());
    Some(17)
}

/// A parsed `SSH_MSG_CHANNEL_REQUEST` (RFC4254 §5.4): only `exec` is
/// understood; `exec_command` is empty for any other request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChannelRequest<'a> {
    pub recipient_channel: u32,
    pub request_type: &'a [u8],
    pub want_reply: bool,
    pub exec_command: &'a [u8],
}

/// Parse a complete `SSH_MSG_CHANNEL_REQUEST` **payload**. An `exec`
/// request must carry a non-empty command within [`EXEC_COMMAND_MAX`].
pub fn parse_channel_request(payload: &[u8]) -> Result<ChannelRequest<'_>, ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_CHANNEL_REQUEST {
        return Err(ChannelError::WrongMessage);
    }
    let recipient_channel = r.u32().map_err(read)?;
    let tlen = r.u32().map_err(read)?;
    let tlen = usize::try_from(tlen).map_err(|_| ChannelError::Truncated)?;
    let request_type = r.take(tlen).map_err(read)?;
    let want_reply = match r.u8().map_err(read)? {
        0 => false,
        1 => true,
        _ => return Err(ChannelError::BadBoolean),
    };
    let exec_command = if request_type == b"exec" {
        let clen = r.u32().map_err(read)?;
        let clen = usize::try_from(clen).map_err(|_| ChannelError::Truncated)?;
        if clen == 0 || clen > EXEC_COMMAND_MAX {
            return Err(ChannelError::BadCommand);
        }
        r.take(clen).map_err(read)?
    } else {
        &[]
    };
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok(ChannelRequest {
        recipient_channel,
        request_type,
        want_reply,
        exec_command,
    })
}

/// Encode `SSH_MSG_CHANNEL_REQUEST` for `exec`.
pub fn channel_request_exec_payload(
    recipient_channel: u32,
    command: &[u8],
    want_reply: bool,
    out: &mut [u8],
) -> Option<usize> {
    if command.is_empty() || command.len() > EXEC_COMMAND_MAX {
        return None;
    }
    let total = 1usize + 4 + 4 + 4 + 1 + 4 + command.len();
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_CHANNEL_REQUEST;
    dst[1..5].copy_from_slice(&recipient_channel.to_be_bytes());
    let mut w = 5usize;
    w += encode_string(b"exec", &mut dst[w..])?;
    dst[w] = u8::from(want_reply);
    w += 1;
    w += encode_string(command, &mut dst[w..])?;
    Some(w)
}

/// Parse the single channel number of `CHANNEL_SUCCESS`/`FAILURE`/
/// `EOF`/`CLOSE`/`WINDOW_ADJUST`.
pub fn parse_channel_number(payload: &[u8], expected: u8) -> Result<u32, ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != expected {
        return Err(ChannelError::WrongMessage);
    }
    let channel = r.u32().map_err(read)?;
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok(channel)
}

/// Encode a one-channel message (`CHANNEL_SUCCESS`, `CHANNEL_FAILURE`,
/// `CHANNEL_EOF`, `CHANNEL_CLOSE`).
pub fn channel_number_payload(msg: u8, channel: u32, out: &mut [u8]) -> Option<usize> {
    if !matches!(
        msg,
        SSH_MSG_CHANNEL_SUCCESS
            | SSH_MSG_CHANNEL_FAILURE
            | SSH_MSG_CHANNEL_EOF
            | SSH_MSG_CHANNEL_CLOSE
    ) {
        return None;
    }
    let dst = out.get_mut(..5)?;
    dst[0] = msg;
    dst[1..5].copy_from_slice(&channel.to_be_bytes());
    Some(5)
}

/// Parse `SSH_MSG_CHANNEL_DATA`: recipient channel + `string` data.
pub fn parse_channel_data(payload: &[u8]) -> Result<(u32, &[u8]), ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_CHANNEL_DATA {
        return Err(ChannelError::WrongMessage);
    }
    let channel = r.u32().map_err(read)?;
    let dlen = r.u32().map_err(read)?;
    let dlen = usize::try_from(dlen).map_err(|_| ChannelError::Truncated)?;
    let data = r.take(dlen).map_err(read)?;
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok((channel, data))
}

/// Encode `SSH_MSG_CHANNEL_DATA`.
pub fn channel_data_payload(channel: u32, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let total = 1usize
        .checked_add(4)?
        .checked_add(4)?
        .checked_add(data.len())?;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_CHANNEL_DATA;
    dst[1..5].copy_from_slice(&channel.to_be_bytes());
    let n = encode_string(data, &mut dst[5..])?;
    Some(5 + n)
}

/// Encode the `exit-status` channel request (RFC4254 §6.10) — no reply
/// is wanted, the channel is ending either way.
pub fn channel_exit_status_payload(channel: u32, status: u32, out: &mut [u8]) -> Option<usize> {
    let total = 1usize + 4 + 4 + 11 + 1 + 4;
    let dst = out.get_mut(..total)?;
    dst[0] = SSH_MSG_CHANNEL_REQUEST;
    dst[1..5].copy_from_slice(&channel.to_be_bytes());
    let mut w = 5usize;
    w += encode_string(b"exit-status", &mut dst[w..])?;
    dst[w] = 0; // want_reply = false
    w += 1;
    dst[w..w + 4].copy_from_slice(&status.to_be_bytes());
    Some(w + 4)
}

/// Parse an `exit-status` channel request: `(recipient, status)`.
pub fn parse_channel_exit_status(payload: &[u8]) -> Result<(u32, u32), ChannelError> {
    let read = |_: KexError| ChannelError::Truncated;
    let mut r = Reader {
        buf: payload,
        pos: 0,
    };
    if r.u8().map_err(read)? != SSH_MSG_CHANNEL_REQUEST {
        return Err(ChannelError::WrongMessage);
    }
    let channel = r.u32().map_err(read)?;
    let tlen = r.u32().map_err(read)?;
    if tlen != 11 {
        return Err(ChannelError::WrongMessage);
    }
    if r.take(11).map_err(read)? != b"exit-status" {
        return Err(ChannelError::WrongMessage);
    }
    if r.u8().map_err(read)? > 1 {
        return Err(ChannelError::BadBoolean);
    }
    let status = r.u32().map_err(read)?;
    if r.pos != payload.len() {
        return Err(ChannelError::TrailingGarbage);
    }
    Ok((channel, status))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes128;
    use aes::cipher::{KeyIvInit, StreamCipher};
    use ctr::Ctr128BE;
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    /// Frame `payload` with `pad` padding bytes; the caller picks `pad`
    /// so the result is a *legal* packet (illegal ones get their own
    /// hand-built headers below).
    fn frame(payload: &[u8], pad: usize) -> Vec<u8> {
        let packet_length = 1 + payload.len() + pad;
        let mut v = Vec::new();
        v.extend_from_slice(&(packet_length as u32).to_be_bytes());
        v.push(pad as u8);
        v.extend_from_slice(payload);
        v.extend(std::iter::repeat_n(0u8, pad));
        v
    }

    /// A hand-built KEXINIT payload with full control over every field.
    fn payload(lists: [&[u8]; 10], follows: u8, reserved: u32, msg: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(msg);
        v.extend_from_slice(&[0x42u8; 16]);
        for list in lists {
            v.extend_from_slice(&(list.len() as u32).to_be_bytes());
            v.extend_from_slice(list);
        }
        v.push(follows);
        v.extend_from_slice(&reserved.to_be_bytes());
        v
    }

    /// All ten lists filled with something legal (languages empty).
    fn full_lists(kex: &'static [u8]) -> [&'static [u8]; 10] {
        [
            kex,
            b"ssh-ed25519",
            b"aes128-ctr,aes256-ctr",
            b"aes128-ctr,aes256-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ]
    }

    /// Our own framed packet's payload, for roundtrip/truncation tests.
    fn ours_payload() -> Vec<u8> {
        let mut wire = [0u8; KEXINIT_WIRE_MAX];
        let n = encode_kexinit(&[0x11; 16], &mut wire).expect("fits");
        match decode_packet(&wire[..n]) {
            PacketStep::Done { payload, .. } => payload.to_vec(),
            other => panic!("encoder produced an undecodable packet: {other:?}"),
        }
    }

    // ---- banner (RFC4253 §4.2) ------------------------------------

    #[test]
    fn banner_accepts_v2_and_v199() {
        for line in [
            b"SSH-2.0-OpenSSH_9.6\r\n".as_slice(),
            b"SSH-2.0-reemplazo_0.1\r\n",
            // Debian's long but legal banner (comment after a space).
            b"SSH-2.0-OpenSSH_9.2 Debian-3+deb12u5\r\n",
            // 1.99 reads as 2.0.
            b"SSH-1.99-legacy_1.0\r\n",
        ] {
            match decode_banner(line) {
                BannerStep::Done { consumed, ident } => {
                    assert_eq!(consumed, line.len(), "line {line:?}");
                    assert_eq!(ident, &line[..line.len() - 2], "line {line:?}");
                }
                other => panic!("line {line:?}: expected Done, got {other:?}"),
            }
        }
    }

    #[test]
    fn banner_rejects_incompatible_versions() {
        for bad in [
            b"SSH-1.5-ssh_1.0\r\n".as_slice(), // SSH-1.xx
            b"SSH-1.0-old\r\n",
            b"SSH-0.9-ancient\r\n",
            b"HTTP/1.1 200 OK\r\n",
            b"not-ssh-at-all\r\n",
            b"SSH-2.0-\r\n", // empty software version
            b"SSH-1.99\r\n", // truncated prefix (no `-version`)
        ] {
            assert_eq!(
                decode_banner(bad),
                BannerStep::Failed(BannerError::Incompatible),
                "accepted {bad:?}"
            );
        }
    }

    #[test]
    fn banner_rejects_bad_line_endings() {
        assert_eq!(
            decode_banner(b"SSH-2.0-x\n"),
            BannerStep::Failed(BannerError::BadEol)
        );
        // Embedded LF before the prefix ends.
        assert_eq!(
            decode_banner(b"SSH-\n2.0-evil\r\n"),
            BannerStep::Failed(BannerError::BadEol)
        );
        // CR not followed by LF ("missing CRLF").
        assert_eq!(
            decode_banner(b"SSH-2.0-x\rjunk\r\n"),
            BannerStep::Failed(BannerError::BadEol)
        );
        // CR seen, LF may still arrive.
        assert_eq!(decode_banner(b"SSH-2.0-x\r"), BannerStep::Incomplete);
        assert_eq!(decode_banner(b""), BannerStep::Incomplete);
        assert_eq!(decode_banner(b"SSH"), BannerStep::Incomplete);
    }

    #[test]
    fn banner_feeds_one_byte_at_a_time() {
        let line = b"SSH-2.0-OpenSSH_9.6\r\n";
        for split in 0..line.len() {
            assert_eq!(
                decode_banner(&line[..split]),
                BannerStep::Incomplete,
                "split {split}"
            );
        }
        match decode_banner(line) {
            BannerStep::Done { consumed, ident } => {
                assert_eq!(
                    (consumed, ident),
                    (line.len(), b"SSH-2.0-OpenSSH_9.6".as_slice())
                );
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn banner_enforces_the_255_byte_bound() {
        // 255 bytes (the bound includes CRLF) with no CRLF: too long.
        let mut long = Vec::from(&b"SSH-2.0-"[..]);
        long.extend(std::iter::repeat_n(b'a', BANNER_MAX - 8));
        assert_eq!(long.len(), BANNER_MAX);
        assert_eq!(
            decode_banner(&long),
            BannerStep::Failed(BannerError::TooLong)
        );
        // One byte past the bound, refused without scanning further.
        long.push(b'\r');
        assert_eq!(
            decode_banner(&long),
            BannerStep::Failed(BannerError::TooLong)
        );
        // A CR at index 254 has no room for its LF (254 + 2 > 255).
        let mut cr_last = vec![b'a'; BANNER_MAX - 1];
        cr_last.push(b'\r');
        assert_eq!(cr_last.len(), BANNER_MAX);
        assert_eq!(
            decode_banner(&cr_last),
            BannerStep::Failed(BannerError::TooLong)
        );
        // A CR at index 253 + LF at 254 = exactly 255 bytes: the
        // bound is met — it fails only because "aaa…" is not a
        // version string, i.e. *not* on length.
        let mut exact = vec![b'a'; BANNER_MAX - 2];
        exact.extend_from_slice(b"\r\n");
        assert_eq!(exact.len(), BANNER_MAX);
        assert_eq!(
            decode_banner(&exact),
            BannerStep::Failed(BannerError::Incompatible)
        );
        // ...and with a valid prefix it completes at exactly 255.
        let mut exact_ok = Vec::from(&b"SSH-2.0-"[..]);
        exact_ok.extend(std::iter::repeat_n(b'a', BANNER_MAX - 8 - 2));
        exact_ok.extend_from_slice(b"\r\n");
        assert_eq!(exact_ok.len(), BANNER_MAX);
        match decode_banner(&exact_ok) {
            BannerStep::Done { consumed, .. } => assert_eq!(consumed, BANNER_MAX),
            other => panic!("expected Done at exactly {BANNER_MAX}, got {other:?}"),
        }
    }

    #[test]
    fn banner_rejects_bad_chars_but_allows_comments() {
        // Space where the software version must start.
        assert_eq!(
            decode_banner(b"SSH-2.0- has_space\r\n"),
            BannerStep::Failed(BannerError::BadChar)
        );
        // Control byte inside the version.
        assert_eq!(
            decode_banner(b"SSH-2.0-Open\x01SSH\r\n"),
            BannerStep::Failed(BannerError::BadChar)
        );
        // DEL (0x7F) is outside printable ASCII.
        assert_eq!(
            decode_banner(b"SSH-2.0-OpenSSH\x7f\r\n"),
            BannerStep::Failed(BannerError::BadChar)
        );
        // Non-ASCII byte (e.g. UTF-8 in the comment).
        assert_eq!(
            decode_banner("SSH-2.0-OpenSSH_9.6 café\r\n".as_bytes()),
            BannerStep::Failed(BannerError::BadChar)
        );
        // Spaces in the *comment* part are legal.
        assert!(matches!(
            decode_banner(b"SSH-2.0-OpenSSH_9.6 build 42\r\n"),
            BannerStep::Done { .. }
        ));
    }

    // ---- binary packet framing (RFC4253 §6) -----------------------

    #[test]
    fn packet_feeds_one_byte_at_a_time() {
        // payload = SSH_MSG_NEWKEYS (21); pad makes 4 + 1 + 1 + pad a
        // multiple of 8 → pad = 10 (2 would be below MIN_PADDING).
        let wire = frame(&[21], 10);
        assert_eq!(wire.len() % 8, 0, "test packet must be block-aligned");
        for split in 0..wire.len() {
            assert_eq!(
                decode_packet(&wire[..split]),
                PacketStep::Incomplete,
                "split {split}"
            );
        }
        match decode_packet(&wire) {
            PacketStep::Done { consumed, payload } => {
                assert_eq!((consumed, payload), (wire.len(), &[21][..]));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn packet_rejects_declared_length_claims() {
        // All judged on the four header bytes alone — before any of
        // the declared body is waited on.
        let header = |pl: u32| pl.to_be_bytes();
        // packet_length < 5 (4 is block-aligned but too small).
        for pl in [0u32, 1, 4] {
            assert_eq!(
                decode_packet(&header(pl)),
                PacketStep::Failed(PacketError::TooSmall),
                "pl {pl}"
            );
        }
        // 4 + packet_length not a multiple of the 8-byte block.
        for pl in [5u32, 6, 7, 9] {
            assert_eq!(
                decode_packet(&header(pl)),
                PacketStep::Failed(PacketError::Misaligned),
                "pl {pl}"
            );
        }
        // Absurd declared length: refused even though 40_004 *is*
        // block-aligned (would otherwise stall a 40 KiB read).
        assert_eq!(
            decode_packet(&header(40_004)),
            PacketStep::Failed(PacketError::TooLarge)
        );
        assert_eq!(
            decode_packet(&header(0xFFFF_FFFF)),
            PacketStep::Failed(PacketError::TooLarge)
        );
        // Boundary sanity: the largest aligned length under the cap
        // (34_996 + 4 = 35_000, block-aligned) passes the claim
        // checks and just waits for bytes; 35_000 itself is refused
        // (misaligned — and if it were aligned it would be over the
        // cap, refused as TooLarge).
        assert_eq!(decode_packet(&header(34_996)), PacketStep::Incomplete);
        assert_eq!(
            decode_packet(&header(35_000)),
            PacketStep::Failed(PacketError::Misaligned)
        );
    }

    #[test]
    fn packet_rejects_bad_padding() {
        // pl = 12 (4 + 12 = 16, aligned). Feed the 5 header bytes.
        let mut head = [0u8; 5];
        head[..4].copy_from_slice(&12u32.to_be_bytes());
        // padding below the mandatory 4 bytes.
        for pad in [0u8, 1, 3] {
            head[4] = pad;
            assert_eq!(
                decode_packet(&head),
                PacketStep::Failed(PacketError::BadPadding),
                "pad {pad}"
            );
        }
        // padding_length runs past packet_length (255 is absurd).
        for pad in [12u8, 255] {
            head[4] = pad;
            assert_eq!(
                decode_packet(&head),
                PacketStep::Failed(PacketError::BadPadding),
                "pad {pad}"
            );
        }
        // padding = 11 leaves payload = 12 - 1 - 11 = 0 bytes: no
        // message-type byte exists.
        head[4] = 11;
        assert_eq!(
            decode_packet(&head),
            PacketStep::Failed(PacketError::EmptyPayload)
        );
        // Legal padding = 4 → payload of 7.
        head[4] = 4;
        let mut wire = head.to_vec();
        wire.extend_from_slice(b"message");
        wire.extend_from_slice(&[0u8; 4]);
        match decode_packet(&wire) {
            PacketStep::Done { consumed, payload } => {
                assert_eq!((consumed, payload), (16, b"message".as_slice()));
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn packet_stays_incomplete_until_the_whole_body_arrives() {
        let wire = frame(b"some payload", 7); // 4 + 1 + 12 + 7 = 24 ✓ aligned
        for split in [4usize, 5, 6, 16, 23] {
            assert_eq!(
                decode_packet(&wire[..split]),
                PacketStep::Incomplete,
                "split {split}"
            );
        }
        // Declared but never delivered: stays Incomplete forever —
        // the caller's bounded read turns that into a fatal timeout.
        let mut declared = Vec::from(&(100u32.to_be_bytes())[..]);
        declared.push(4);
        declared.extend_from_slice(&[0u8; 91]); // 4 + 100 = 104 total; 99 fed
        assert_eq!(decode_packet(&declared), PacketStep::Incomplete);
    }

    // ---- SSH_MSG_KEXINIT (RFC4253 §7.1) ---------------------------

    #[test]
    fn kexinit_roundtrip_from_encoder() {
        let mut wire = [0u8; KEXINIT_WIRE_MAX];
        let n = encode_kexinit(&[0xA1; 16], &mut wire).expect("fits");
        assert!(n <= KEXINIT_WIRE_MAX);
        assert_eq!(n % 8, 0, "unencrypted packets are block-aligned");
        let parsed = match decode_packet(&wire[..n]) {
            PacketStep::Done { consumed, payload } => {
                assert_eq!(consumed, n);
                parse_kexinit(payload).expect("roundtrip parses")
            }
            other => panic!("framing roundtrip failed: {other:?}"),
        };
        assert_eq!(parsed.cookie, &[0xA1; 16][..]);
        assert_eq!(parsed.kex_algorithms, KEX_ALGORITHMS.as_bytes());
        assert_eq!(
            parsed.server_host_key_algorithms,
            HOST_KEY_ALGORITHMS.as_bytes()
        );
        assert_eq!(
            parsed.encryption_algorithms_c2s,
            ENCRYPTION_ALGORITHMS.as_bytes()
        );
        assert_eq!(
            parsed.encryption_algorithms_s2c,
            ENCRYPTION_ALGORITHMS.as_bytes()
        );
        assert_eq!(parsed.mac_algorithms_c2s, MAC_ALGORITHMS.as_bytes());
        assert_eq!(parsed.mac_algorithms_s2c, MAC_ALGORITHMS.as_bytes());
        assert_eq!(
            parsed.compression_algorithms_c2s,
            COMPRESSION_ALGORITHMS.as_bytes()
        );
        assert_eq!(
            parsed.compression_algorithms_s2c,
            COMPRESSION_ALGORITHMS.as_bytes()
        );
        assert!(parsed.language_c2s.is_empty());
        assert!(parsed.language_s2c.is_empty());
        assert!(!parsed.first_kex_packet_follows);
        assert_eq!(parsed.reserved, 0);
    }

    #[test]
    fn kexinit_rejects_every_truncation() {
        let full = ours_payload();
        for cut in 0..full.len() {
            let err = match parse_kexinit(&full[..cut]) {
                Err(e) => e,
                Ok(_) => panic!("cut {cut} parsed as a complete KEXINIT"),
            };
            // Every prefix must be refused — truncation is never a
            // partially-parsed KEXINIT.
            assert!(
                matches!(err, KexError::Truncated | KexError::EmptyList),
                "cut {cut}: {err:?}"
            );
        }
        assert!(parse_kexinit(&full).is_ok());
    }

    #[test]
    fn kexinit_rejects_malformed_name_lists() {
        let ok = full_lists(b"curve25519-sha256");
        // Empty negotiation-relevant list.
        let mut lists = ok;
        lists[0] = b"";
        assert_eq!(
            parse_kexinit(&payload(lists, 0, 0, SSH_MSG_KEXINIT)),
            Err(KexError::EmptyList)
        );
        // Declared length runs past the payload (0xFFFFFFFF).
        let mut huge = Vec::new();
        huge.push(SSH_MSG_KEXINIT);
        huge.extend_from_slice(&[0u8; 16]);
        huge.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(parse_kexinit(&huge), Err(KexError::Truncated));
        // Space / control / non-ASCII bytes and empty names.
        for bad in [
            b"curve25519 sha256".as_slice(),
            b"curve25519-sha256,",
            b",curve25519-sha256",
            b"curve25519-sha256,,diffie-hellman",
            b"curve25519-sha256\x7f",
            "curve25519-sha256é".as_bytes(),
            b"\x00\x01\x02",
        ] {
            let mut lists = ok;
            lists[0] = bad;
            assert_eq!(
                parse_kexinit(&payload(lists, 0, 0, SSH_MSG_KEXINIT)),
                Err(KexError::BadNameList),
                "accepted name-list {bad:?}"
            );
        }
        // Empty *language* lists are legal (never negotiated).
        let lists = full_lists(b"curve25519-sha256");
        assert!(parse_kexinit(&payload(lists, 0, 0, SSH_MSG_KEXINIT)).is_ok());
        // `@`/`-`/`.`/`_` vendor names are legal.
        let mut lists = ok;
        lists[4] = b"hmac-sha2-256@openssh.com,hmac-sha2-256";
        assert!(parse_kexinit(&payload(lists, 0, 0, SSH_MSG_KEXINIT)).is_ok());
    }

    #[test]
    fn kexinit_rejects_wrong_message_bad_boolean_and_trailing_garbage() {
        let lists = full_lists(b"curve25519-sha256");
        // NEWKEYS (21) instead of KEXINIT (20).
        assert_eq!(
            parse_kexinit(&payload(lists, 0, 0, 21)),
            Err(KexError::WrongMessage)
        );
        // first_kex_packet_follows = 2 is not a boolean.
        assert_eq!(
            parse_kexinit(&payload(lists, 2, 0, SSH_MSG_KEXINIT)),
            Err(KexError::BadBoolean)
        );
        // A byte after the reserved field has no business being there.
        let mut full = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        full.push(0);
        assert_eq!(parse_kexinit(&full), Err(KexError::TrailingGarbage));
        // Empty payload.
        assert_eq!(parse_kexinit(&[]), Err(KexError::Truncated));
    }

    #[test]
    fn kexinit_records_first_kex_packet_follows_and_reserved() {
        let lists = full_lists(b"curve25519-sha256");
        let bytes = payload(lists, 1, 0xDEAD_BEEF, SSH_MSG_KEXINIT);
        let parsed = parse_kexinit(&bytes).expect("legal payload");
        assert!(parsed.first_kex_packet_follows);
        // Recorded, not enforced (RFC: the receiver must ignore it).
        assert_eq!(parsed.reserved, 0xDEAD_BEEF);
    }

    // ---- intersection (RFC4253 §7.1) ------------------------------

    /// A GitHub-like server KEXINIT: everything we need, in an order
    /// that is *not* ours, plus extras we do not offer.
    fn github_like_payload() -> Vec<u8> {
        payload(
            [
                b"ecdh-sha2-nistp256,curve25519-sha256,diffie-hellman-group-exchange-sha256",
                b"ssh-ed25519,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256",
                b"aes256-ctr,aes128-ctr,chacha20-poly1305@openssh.com",
                b"aes256-ctr,aes128-ctr",
                b"hmac-sha2-256,hmac-sha2-512",
                b"hmac-sha2-256",
                b"none,zlib@openssh.com",
                b"none",
                b"",
                b"",
            ],
            0,
            0,
            SSH_MSG_KEXINIT,
        )
    }

    #[test]
    fn intersect_picks_the_first_client_side_match() {
        let bytes = github_like_payload();
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        // Server lists nistp256 first — but RFC4253 §7.1 is
        // client-preference: our first list entry that exists on the
        // server wins (the trailing `ext-info-c` signal is not a kex —
        // it is never selected as one).
        assert_eq!(n.kex, Some(KEX_CHOSEN));
        assert_eq!(n.host_key, Some(HOST_KEY_ALGORITHMS));
        // Server lists aes256-ctr first; our list has aes128-ctr
        // first → aes128-ctr, independently for each direction.
        assert_eq!(n.enc_c2s, Some("aes128-ctr"));
        assert_eq!(n.enc_s2c, Some("aes128-ctr"));
        assert_eq!(n.mac_c2s, Some(MAC_ALGORITHMS));
        assert_eq!(n.mac_s2c, Some(MAC_ALGORITHMS));
        assert_eq!(n.comp_c2s, Some(COMPRESSION_ALGORITHMS));
        assert_eq!(n.comp_s2c, Some(COMPRESSION_ALGORITHMS));
        check_must_have(&n).expect("GitHub-like server passes the gate");
    }

    #[test]
    fn intersect_falls_back_to_the_second_client_choice() {
        // Server only offers our second cipher choice.
        let mut lists = full_lists(b"curve25519-sha256");
        lists[2] = b"aes256-ctr";
        lists[3] = b"aes256-ctr";
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.enc_c2s, Some("aes256-ctr"));
        assert_eq!(n.enc_s2c, Some("aes256-ctr"));
        check_must_have(&n).expect("aes256-ctr-only still passes");
    }

    #[test]
    fn intersect_returns_none_without_overlap() {
        // Server kex list doesn't contain ours.
        let mut lists = full_lists(b"ecdh-sha2-nistp256");
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.kex, None);
        assert_eq!(check_must_have(&n), Err(Missing::Kex));

        // Cipher gap in one direction only — the other passes.
        lists = full_lists(b"curve25519-sha256");
        lists[3] = b"3des-cbc";
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.enc_c2s, Some("aes128-ctr"));
        assert_eq!(n.enc_s2c, None);
        assert_eq!(check_must_have(&n), Err(Missing::EncS2c));

        // A near-miss MAC name (the @openssh variant alone).
        lists = full_lists(b"curve25519-sha256");
        lists[4] = b"hmac-sha2-256@openssh.com";
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.mac_c2s, None);
        assert_eq!(check_must_have(&n), Err(Missing::MacC2s));

        // Host key gap.
        lists = full_lists(b"curve25519-sha256");
        lists[1] = b"ecdsa-sha2-nistp256";
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.host_key, None);
        assert_eq!(check_must_have(&n), Err(Missing::HostKey));

        // Compression gap.
        lists = full_lists(b"curve25519-sha256");
        lists[6] = b"zlib@openssh.com";
        lists[7] = b"zlib@openssh.com";
        let bytes = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let server = parse_kexinit(&bytes).expect("parses");
        let n = intersect(&server);
        assert_eq!(n.comp_c2s, None);
        assert_eq!(n.comp_s2c, None);
        assert_eq!(check_must_have(&n), Err(Missing::CompC2s));
    }

    #[test]
    fn namelist_contains_matches_whole_names_only() {
        assert!(namelist_contains(b"aes128-ctr,aes256-ctr", b"aes128-ctr"));
        assert!(namelist_contains(b"aes128-ctr,aes256-ctr", b"aes256-ctr"));
        // Substring is not membership.
        assert!(!namelist_contains(b"aes128-ctr,aes256-ctr", b"aes128"));
        assert!(!namelist_contains(b"aes128-ctr", b""));
        assert!(!namelist_contains(b"", b"aes128-ctr"));
        // first_common: client order decides, not server order.
        assert_eq!(
            first_common(
                b"curve25519-sha256,ecdh-sha2-nistp256",
                b"ecdh-sha2-nistp256,curve25519-sha256"
            ),
            Some("curve25519-sha256")
        );
        assert_eq!(first_common(b"one,two", b"three"), None);
    }

    // ---- encoder bounds -------------------------------------------

    #[test]
    fn encoder_refuses_to_overflow_and_zeroes_its_padding() {
        let mut wire = [0xAAu8; KEXINIT_WIRE_MAX]; // caller garbage
        let n = encode_kexinit(&[0x5A; 16], &mut wire).expect("fits");
        assert!(n <= KEXINIT_WIRE_MAX);
        // One byte short must fail; exact succeeds.
        assert_eq!(encode_kexinit(&[0x5A; 16], &mut wire[..n - 1]), None);
        assert_eq!(encode_kexinit(&[0x5A; 16], &mut wire[..n]), Some(n));
        // Absurdly small buffers fail, not panic.
        assert_eq!(encode_kexinit(&[0x5A; 16], &mut []), None);
        assert_eq!(encode_kexinit(&[0x5A; 16], &mut [0u8; 64]), None);
        // The padding tail must be zeros even though the caller's
        // buffer was full of 0xAA.
        let packet_length = u32::from_be_bytes(wire[..4].try_into().expect("4 bytes")) as usize;
        let padding = usize::from(wire[4]);
        assert!(padding >= MIN_PADDING);
        assert_eq!(4 + packet_length, n);
        assert!(wire[n - padding..n].iter().all(|&b| b == 0));
    }

    // ---- S2: RFC4251 mpint / string (exchange hash + KDF inputs) --

    #[test]
    fn mpint_matches_openssh_encoding() {
        let mut out = [0u8; 64];
        // No high bit: uint32 length + bytes.
        assert_eq!(encode_mpint(&[0x01, 0x02], &mut out), Some(6));
        assert_eq!(&out[..6], &[0, 0, 0, 2, 0x01, 0x02]);
        // High bit set: a 0x00 is prepended *and counted* in the
        // length (OpenSSH `sshbuf_put_bignum2_bytes`).
        assert_eq!(encode_mpint(&[0x80, 0x01], &mut out), Some(7));
        assert_eq!(&out[..7], &[0, 0, 0, 3, 0x00, 0x80, 0x01]);
        // Leading zeros are stripped before the high-bit test.
        assert_eq!(encode_mpint(&[0x00, 0x00, 0x01], &mut out), Some(5));
        assert_eq!(&out[..5], &[0, 0, 0, 1, 0x01]);
        assert_eq!(encode_mpint(&[0x00, 0x80], &mut out), Some(6));
        assert_eq!(&out[..6], &[0, 0, 0, 2, 0x00, 0x80]);
        // Zero is the empty mpint (length 0).
        assert_eq!(encode_mpint(&[0x00, 0x00], &mut out), Some(4));
        assert_eq!(&out[..4], &[0, 0, 0, 0]);
        // A high-bit X25519 shared secret (the common case): 4 + 33.
        let k = [0xFFu8; 32];
        assert_eq!(encode_mpint(&k, &mut out), Some(37));
        assert_eq!(out[..5], [0, 0, 0, 33, 0x00]);
        // One byte short must fail; exact succeeds.
        assert_eq!(encode_mpint(&[0x80, 0x01], &mut out[..6]), None);
        assert_eq!(encode_mpint(&[0x80, 0x01], &mut out[..7]), Some(7));
    }

    #[test]
    fn encode_string_prefixes_the_length() {
        let mut out = [0u8; 16];
        assert_eq!(encode_string(b"abc", &mut out), Some(7));
        assert_eq!(&out[..7], &[0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(encode_string(b"", &mut out), Some(4));
        assert_eq!(&out[..4], &[0, 0, 0, 0]);
        // One byte short must fail; exact succeeds.
        assert_eq!(encode_string(b"abcd", &mut out[..7]), None);
        assert_eq!(encode_string(b"abcd", &mut out[..8]), Some(8));
    }

    // ---- S2: encrypted-phase framing (RFC4253 §6) ------------------

    #[test]
    fn encode_packet_aligns_and_fills_padding() {
        let mut out = [0u8; 256];
        // block 8, one-byte payload: unpadded 6 → pad 2 < 4 → +8 =
        // 10; total 16.
        let n = encode_packet(&[21], 8, |p| p.fill(0xAA), &mut out).expect("fits");
        assert_eq!(n, 16);
        assert_eq!(n % 8, 0);
        assert_eq!(out[4], 10); // padding_length
        assert_eq!(&out[5..6], &[21]);
        assert!(out[6..n].iter().all(|&b| b == 0xAA)); // exactly the pad
        // block 16 (encrypted phase), three-byte payload: unpadded 8
        // → pad 8; total 16.
        let n = encode_packet(&[5, 0, 0], 16, |p| p.fill(0xBB), &mut out).expect("fits");
        assert_eq!(n, 16);
        assert_eq!(n % 16, 0);
        assert_eq!(out[4], 8);
        assert!(out[8..n].iter().all(|&b| b == 0xBB));
        // Padding ≥ 4 and alignment hold for every payload size, in
        // both block modes (the "recompute after the payload changed"
        // property the encrypted phase depends on).
        let payload = [0x42u8; 40];
        for len in 1..payload.len() {
            for block in [8usize, 16] {
                let n =
                    encode_packet(&payload[..len], block, |p| p.fill(0), &mut out).expect("fits");
                assert_eq!(n % block, 0, "len {len} block {block}");
                assert!(out[4] >= MIN_PADDING as u8, "len {len} block {block}");
                assert_eq!(n, 4 + 1 + len + usize::from(out[4]));
            }
        }
        // Refusals: empty payload, unusable block, tiny output.
        assert_eq!(encode_packet(&[], 16, |p| p.fill(0), &mut out), None);
        assert_eq!(encode_packet(&[21], 4, |p| p.fill(0), &mut out), None);
        assert_eq!(encode_packet(&[21], 8, |p| p.fill(0), &mut out[..15]), None);
        assert_eq!(
            encode_packet(&[21], 8, |p| p.fill(0), &mut out[..16]),
            Some(16)
        );
    }

    #[test]
    fn decode_packet_block_generalises_the_block_size() {
        let mut wire = [0u8; 64];
        let n = encode_packet(&[21], 16, |p| p.fill(7), &mut wire).expect("fits");
        match decode_packet_block(&wire[..n], 16) {
            PacketStep::Done { consumed, payload } => {
                assert_eq!(consumed, n);
                assert_eq!(payload, &[21]);
            }
            other => panic!("expected Done for block 16, got {other:?}"),
        }
        // 16-aligned is also 8-aligned: the plaintext wrapper decodes
        // it too.
        assert!(matches!(decode_packet(&wire[..n]), PacketStep::Done { .. }));
        // An 8-aligned but not 16-aligned packet (total 24) is refused
        // under block 16 and accepted under block 8.
        let n = encode_packet(&[0u8; 12], 8, |p| p.fill(0), &mut wire).expect("fits");
        assert_eq!(n, 24);
        assert_eq!(
            decode_packet_block(&wire[..n], 16),
            PacketStep::Failed(PacketError::Misaligned)
        );
        assert!(matches!(
            decode_packet_block(&wire[..n], 8),
            PacketStep::Done { .. }
        ));
        // A zero block is refused, never a divide-by-zero.
        assert_eq!(
            decode_packet_block(&wire[..n], 0),
            PacketStep::Failed(PacketError::Misaligned)
        );
    }

    #[test]
    fn packet_total_bounds_before_waiting() {
        assert_eq!(packet_total(&[], 16), Ok(None));
        assert_eq!(packet_total(&[0, 0], 16), Ok(None));
        // pl = 60 → total 64: aligned for both blocks.
        assert_eq!(packet_total(&60u32.to_be_bytes(), 16), Ok(Some(64)));
        assert_eq!(packet_total(&60u32.to_be_bytes(), 8), Ok(Some(64)));
        // pl = 52 → total 56: 8-aligned, not 16-aligned.
        assert_eq!(packet_total(&52u32.to_be_bytes(), 8), Ok(Some(56)));
        assert_eq!(
            packet_total(&52u32.to_be_bytes(), 16),
            Err(PacketError::Misaligned)
        );
        // Illegal headers fail on the four header bytes alone —
        // before any body is ever waited on.
        assert_eq!(
            packet_total(&4u32.to_be_bytes(), 16),
            Err(PacketError::TooSmall)
        );
        assert_eq!(
            packet_total(&0u32.to_be_bytes(), 16),
            Err(PacketError::TooSmall)
        );
        assert_eq!(
            packet_total(&40_004u32.to_be_bytes(), 16),
            Err(PacketError::TooLarge)
        );
        assert_eq!(
            packet_total(&u32::MAX.to_be_bytes(), 16),
            Err(PacketError::TooLarge)
        );
        assert_eq!(
            packet_total(&60u32.to_be_bytes(), 0),
            Err(PacketError::Misaligned)
        );
    }

    // ---- S2: SSH_MSG_KEXDH_REPLY (RFC4253 §8 / RFC8731 §3) --------

    /// `string "ssh-ed25519" || string key` with a caller-chosen
    /// algorithm name (for the malformed cases).
    fn ed_blob_alg(alg: &[u8], key: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(alg.len() as u32).to_be_bytes());
        v.extend_from_slice(alg);
        v.extend_from_slice(&(key.len() as u32).to_be_bytes());
        v.extend_from_slice(key);
        v
    }

    fn ed_blob(key: &[u8]) -> Vec<u8> {
        ed_blob_alg(b"ssh-ed25519", key)
    }

    fn kexdh_reply_payload(host_key: &[u8], f: &[u8], sig: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(SSH_MSG_KEXDH_REPLY);
        v.extend_from_slice(&(host_key.len() as u32).to_be_bytes());
        v.extend_from_slice(host_key);
        v.extend_from_slice(&(f.len() as u32).to_be_bytes());
        v.extend_from_slice(f);
        v.extend_from_slice(&(sig.len() as u32).to_be_bytes());
        v.extend_from_slice(sig);
        v
    }

    fn valid_kexdh_reply() -> Vec<u8> {
        kexdh_reply_payload(&ed_blob(&[0x11; 32]), &[0x22; 32], &ed_blob(&[0x33; 64]))
    }

    #[test]
    fn kexdh_reply_roundtrip() {
        let p = valid_kexdh_reply();
        let r = parse_kexdh_reply(&p).expect("legal reply");
        assert_eq!(r.host_key, ed_blob(&[0x11; 32]).as_slice());
        assert_eq!(r.host_key_bytes, &[0x11; 32]);
        assert_eq!(r.f, &[0x22; 32]);
        assert_eq!(r.signature, ed_blob(&[0x33; 64]).as_slice());
        assert_eq!(r.signature_bytes, &[0x33; 64]);
    }

    #[test]
    fn kexdh_reply_rejects_every_truncation() {
        let full = valid_kexdh_reply();
        for cut in 0..full.len() {
            match parse_kexdh_reply(&full[..cut]) {
                Err(e) => assert!(
                    matches!(
                        e,
                        KexDhError::Truncated
                            | KexDhError::BadHostKey
                            | KexDhError::BadPublicKey
                            | KexDhError::BadSignature
                    ),
                    "cut {cut}: {e:?}"
                ),
                Ok(_) => panic!("cut {cut} parsed as a complete KEXDH_REPLY"),
            }
        }
        assert!(parse_kexdh_reply(&full).is_ok());
    }

    #[test]
    fn kexdh_reply_rejects_malformed_fields() {
        // Wrong message byte.
        let mut p = valid_kexdh_reply();
        p[0] = SSH_MSG_KEXINIT;
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::WrongMessage));

        // K_S: wrong algorithm, wrong key length, trailing bytes.
        for hk in [
            ed_blob_alg(b"ssh-ed2551X", &[0x11; 32]),
            ed_blob_alg(b"ssh-ed25519", &[0x11; 31]),
            ed_blob_alg(b"ssh-ed25519", &[0x11; 33]),
            {
                let mut v = ed_blob(&[0x11; 32]);
                v.push(0); // nothing may follow the key inside K_S
                v
            },
        ] {
            let p = kexdh_reply_payload(&hk, &[0x22; 32], &ed_blob(&[0x33; 64]));
            assert_eq!(
                parse_kexdh_reply(&p),
                Err(KexDhError::BadHostKey),
                "accepted host key {hk:?}"
            );
        }

        // f: wrong lengths and the all-zero (small-order) point.
        for flen in [31usize, 33] {
            let p = kexdh_reply_payload(
                &ed_blob(&[0x11; 32]),
                &vec![0x22u8; flen],
                &ed_blob(&[0x33; 64]),
            );
            assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::BadPublicKey));
        }
        let p = kexdh_reply_payload(&ed_blob(&[0x11; 32]), &[0u8; 32], &ed_blob(&[0x33; 64]));
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::ZeroPublicKey));

        // Signature: wrong algorithm, wrong lengths, trailing bytes.
        for sig in [
            ed_blob_alg(b"ssh-ed2551X", &[0x33; 64]),
            ed_blob_alg(b"ssh-ed25519", &[0x33; 63]),
            ed_blob_alg(b"ssh-ed25519", &[0x33; 65]),
            {
                let mut v = ed_blob(&[0x33; 64]);
                v.push(0);
                v
            },
        ] {
            let p = kexdh_reply_payload(&ed_blob(&[0x11; 32]), &[0x22; 32], &sig);
            assert_eq!(
                parse_kexdh_reply(&p),
                Err(KexDhError::BadSignature),
                "accepted signature {sig:?}"
            );
        }

        // Nothing may follow the signature.
        let mut p = valid_kexdh_reply();
        p.push(0);
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::TrailingGarbage));
        // Empty payload.
        assert_eq!(parse_kexdh_reply(&[]), Err(KexDhError::Truncated));
    }

    // ---- S2: SSH_MSG_EXT_INFO (RFC8308) ----------------------------

    fn ext_info_payload(count: u32, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(SSH_MSG_EXT_INFO);
        v.extend_from_slice(&count.to_be_bytes());
        for (name, value) in entries {
            v.extend_from_slice(&(name.len() as u32).to_be_bytes());
            v.extend_from_slice(name);
            v.extend_from_slice(&(value.len() as u32).to_be_bytes());
            v.extend_from_slice(value);
        }
        v
    }

    #[test]
    fn ext_info_iterates_and_finishes() {
        let p = ext_info_payload(
            2,
            &[
                (
                    b"server-sig-algs".as_slice(),
                    b"ssh-ed25519,rsa-sha2-512".as_slice(),
                ),
                (b"ping@openssh.com".as_slice(), b"0".as_slice()),
            ],
        );
        let mut info = parse_ext_info(&p).expect("parses");
        assert_eq!(
            info.next_entry().expect("first"),
            Some((
                b"server-sig-algs".as_slice(),
                b"ssh-ed25519,rsa-sha2-512".as_slice()
            ))
        );
        assert_eq!(
            info.next_entry().expect("second"),
            Some((b"ping@openssh.com".as_slice(), b"0".as_slice()))
        );
        assert_eq!(info.next_entry().expect("exhausted"), None);
        info.finish().expect("no trailer");
    }

    #[test]
    fn ext_info_bounds_hostile_counts_and_names() {
        // Count above the cap: refused from the header alone — no
        // entry bytes follow and none are waited on.
        let mut p = Vec::new();
        p.push(SSH_MSG_EXT_INFO);
        p.extend_from_slice(&((EXT_INFO_MAX as u32) + 1).to_be_bytes());
        assert_eq!(parse_ext_info(&p).map(|_| ()), Err(ExtInfoError::TooMany));
        // An absurd u32 count: same refusal, no allocation, no loop.
        p.truncate(1);
        p.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_ext_info(&p).map(|_| ()), Err(ExtInfoError::TooMany));
        // Wrong message byte.
        let mut p = ext_info_payload(0, &[]);
        p[0] = SSH_MSG_NEWKEYS;
        assert_eq!(
            parse_ext_info(&p).map(|_| ()),
            Err(ExtInfoError::WrongMessage)
        );
        // Empty / control-byte / space-bearing names are refused.
        for name in [
            b"".as_slice(),
            b"bad\x01name".as_slice(),
            b"bad name".as_slice(),
        ] {
            let p = ext_info_payload(1, &[(name, b"v".as_slice())]);
            let mut info = parse_ext_info(&p).expect("header parses");
            assert_eq!(
                info.next_entry(),
                Err(ExtInfoError::BadName),
                "name {name:?}"
            );
        }
        // Declared value runs past the payload.
        let mut p = ext_info_payload(1, &[(b"n".as_slice(), b"vv".as_slice())]);
        p.truncate(p.len() - 1);
        let mut info = parse_ext_info(&p).expect("header parses");
        assert_eq!(info.next_entry(), Err(ExtInfoError::Truncated));
        // Bytes after the declared entries.
        let mut p = ext_info_payload(1, &[(b"n".as_slice(), b"v".as_slice())]);
        p.push(0);
        let mut info = parse_ext_info(&p).expect("parses");
        assert_eq!(
            info.next_entry().expect("entry"),
            Some((b"n".as_slice(), b"v".as_slice()))
        );
        assert_eq!(info.next_entry().expect("exhausted"), None);
        assert_eq!(info.finish(), Err(ExtInfoError::TrailingGarbage));
        // Every truncation of a one-entry payload is refused.
        let p = ext_info_payload(1, &[(b"n".as_slice(), b"v".as_slice())]);
        for cut in 0..p.len() {
            let mut info = match parse_ext_info(&p[..cut]) {
                Ok(info) => info,
                Err(e) => {
                    assert!(
                        matches!(e, ExtInfoError::Truncated | ExtInfoError::TooMany),
                        "cut {cut}: {e:?}"
                    );
                    continue;
                }
            };
            assert!(
                info.next_entry().is_err() || info.finish().is_err(),
                "cut {cut} produced a clean entry"
            );
        }
    }

    // ---- S2: service request / none-auth probe ---------------------

    #[test]
    fn service_accept_roundtrip_and_rejections() {
        let mut p = Vec::new();
        p.push(SSH_MSG_SERVICE_ACCEPT);
        p.extend_from_slice(&12u32.to_be_bytes());
        p.extend_from_slice(b"ssh-userauth");
        assert_eq!(parse_service_accept(&p), Ok(b"ssh-userauth".as_slice()));
        // Wrong message byte.
        let mut wrong = p.clone();
        wrong[0] = SSH_MSG_SERVICE_REQUEST;
        assert_eq!(
            parse_service_accept(&wrong),
            Err(ServiceError::WrongMessage)
        );
        // Every truncation fails; trailing bytes fail.
        for cut in 0..p.len() {
            assert!(parse_service_accept(&p[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = p.clone();
        trailing.push(0);
        assert_eq!(
            parse_service_accept(&trailing),
            Err(ServiceError::TrailingGarbage)
        );
    }

    #[test]
    fn userauth_failure_roundtrip_and_rejections() {
        // RFC4252 §5.1 field order: name-list FIRST, then boolean —
        // not the other way around (RFC4254 does not define this
        // message; GitHub's server and OpenSSH's client both use this
        // order).
        fn uaf(methods: &[u8], partial: u8) -> Vec<u8> {
            let mut v = Vec::new();
            v.push(SSH_MSG_USERAUTH_FAILURE);
            v.extend_from_slice(&(methods.len() as u32).to_be_bytes());
            v.extend_from_slice(methods);
            v.push(partial);
            v
        }
        let p = uaf(b"publickey,password", 0);
        let f = parse_userauth_failure(&p).expect("legal");
        assert!(!f.partial_success);
        assert_eq!(f.methods, b"publickey,password".as_slice());
        // partial_success = true parses (the kernel refuses it there).
        let p = uaf(b"none", 1);
        let f = parse_userauth_failure(&p).expect("legal");
        assert!(f.partial_success);

        // Wrong message byte.
        let mut wrong = uaf(b"publickey", 0);
        wrong[0] = SSH_MSG_USERAUTH_REQUEST;
        assert_eq!(
            parse_userauth_failure(&wrong),
            Err(UserAuthError::WrongMessage)
        );
        // partial_success (the trailing byte) is an RFC4251 boolean.
        for byte in [2u8, 9, 255] {
            let bad = uaf(b"publickey", byte);
            assert_eq!(
                parse_userauth_failure(&bad),
                Err(UserAuthError::BadBoolean),
                "accepted partial_success {byte}"
            );
        }
        // Illegal method name-lists (same rules as KEXINIT lists).
        for methods in [
            b"pub lic".as_slice(),
            b"none,".as_slice(),
            b",none".as_slice(),
        ] {
            let bad = uaf(methods, 0);
            assert_eq!(
                parse_userauth_failure(&bad),
                Err(UserAuthError::BadNameList),
                "accepted methods {methods:?}"
            );
        }
        // Every truncation fails; trailing bytes fail.
        let full = uaf(b"publickey,password", 0);
        for cut in 0..full.len() {
            assert!(parse_userauth_failure(&full[..cut]).is_err(), "cut {cut}");
        }
        let mut trailing = full.clone();
        trailing.push(0);
        assert_eq!(
            parse_userauth_failure(&trailing),
            Err(UserAuthError::TrailingGarbage)
        );
    }

    #[test]
    fn kexdh_init_and_auth_payloads_have_exact_wire_shape() {
        let mut out = [0u8; 64];
        let n = kexdh_init_payload(&[0x5A; 32], &mut out).expect("fits");
        assert_eq!(n, 37);
        assert_eq!(out[0], SSH_MSG_KEXDH_INIT);
        assert_eq!(&out[1..5], &[0, 0, 0, 32]);
        assert_eq!(&out[5..37], &[0x5A; 32]);
        assert_eq!(kexdh_init_payload(&[0x5A; 32], &mut out[..36]), None);

        let n = service_request_payload(&mut out).expect("fits");
        assert_eq!(n, 17);
        assert_eq!(out[0], SSH_MSG_SERVICE_REQUEST);
        assert_eq!(&out[1..17], b"\x00\x00\x00\x0cssh-userauth");

        let n = userauth_none_payload(&mut out).expect("fits");
        assert_eq!(n, 34);
        let mut expect = Vec::new();
        expect.push(SSH_MSG_USERAUTH_REQUEST);
        expect.extend_from_slice(&3u32.to_be_bytes());
        expect.extend_from_slice(b"git");
        expect.extend_from_slice(&14u32.to_be_bytes());
        expect.extend_from_slice(b"ssh-connection");
        expect.extend_from_slice(&4u32.to_be_bytes());
        expect.extend_from_slice(b"none");
        assert_eq!(&out[..n], expect.as_slice());
        assert_eq!(userauth_none_payload(&mut out[..33]), None);
    }

    // ---- S2: RFC4253 §7.2 key derivation ---------------------------

    fn hex_of(bytes: &[u8]) -> String {
        let mut s = String::new();
        for b in bytes {
            s.push_str(&std::format!("{b:02x}"));
        }
        s
    }

    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        let mut d = Sha256::new();
        d.update(data);
        d.finalize().into()
    }

    #[test]
    fn kdf_known_answer_letters_and_expansion() {
        // Known-answer vectors generated with an *independent*
        // Python (hashlib) implementation of the RFC4253 §7.2 text:
        // K = 0x01..0x20, H = session_id = 0x21..0x40, mpint(K)
        // stripped/prefixed per RFC4251. RFC4253 carries no test
        // vector of its own, so this pins the composition.
        let k: Vec<u8> = (1u8..=32).collect();
        let h: Vec<u8> = (0x21u8..=0x40).collect();
        let expected: [(u8, &str); 6] = [
            (
                b'A',
                "b5912945de22ed382f019986f834b5dab2761d63e803d81ccf5c585045b33789",
            ),
            (
                b'B',
                "bd8fad0d24e41685f531d68f22ca90b6e2aaecd743ed2b2bc61d54deee6b7df7",
            ),
            (
                b'C',
                "4ca921bf4569ed82a8daafe9a663f6934d997304e3a6ac5cb72f8fe40aea7d10",
            ),
            (
                b'D',
                "ce1c24627709e070328155bb26b07e4e9ace1da957454d37bfac0fd25fd8a6da",
            ),
            (
                b'E',
                "829450113d57507f1f5d3b97dfee5f35e7e9240e0b893f821e8939043f36936f",
            ),
            (
                b'F',
                "0b4aa8944cc322be36621de2d490c97b0d6fdd438db847d753f0ed697a84c479",
            ),
        ];
        for (letter, want) in expected {
            let mut out = [0u8; 32];
            kdf(sha256, &k, &h, letter, &h, &mut out).expect("derives");
            assert_eq!(hex_of(&out), want, "letter {}", letter as char);
        }
        // Expansion past one SHA-256 block: K2 = HASH(mpint(K) || H
        // || K1), key = K1 || K2 (truncated to 64).
        let mut out = [0u8; 64];
        kdf(sha256, &k, &h, b'C', &h, &mut out).expect("derives");
        assert_eq!(
            hex_of(&out),
            "4ca921bf4569ed82a8daafe9a663f6934d997304e3a6ac5cb72f8fe40aea7d10\
             8f9f47854240f1d65044ab822610679c8a1e873e0615a9cc492c047d3f7c1fe5"
        );
        // A high-bit shared secret changes the mpint (0x00 prepended).
        let k2: Vec<u8> = (0x81u8..=0xA0).collect();
        let mut out = [0u8; 32];
        kdf(sha256, &k2, &h, b'A', &h, &mut out).expect("derives");
        assert_eq!(
            hex_of(&out),
            "3b3292c9bb4eabe495af0ff2f5bc4cc366870a4ae7952930941864f56fdc9f8b"
        );
        // Leading zeros strip: K3 = 0x00 0x00 || K derives as K.
        let k3: Vec<u8> = {
            let mut v = vec![0u8; 2];
            v.extend_from_slice(&k);
            v
        };
        let mut out = [0u8; 32];
        kdf(sha256, &k3, &h, b'A', &h, &mut out).expect("derives");
        assert_eq!(hex_of(&out), expected[0].1);
    }

    #[test]
    fn kdf_feeds_the_exact_rfc4253_inputs() {
        // A recording "hash" (no primitive — this crate has none):
        // captures the exact bytes fed to each invocation and returns
        // a distinguishable block, proving the composition
        //   K1 = HASH(mpint(K) || H || X || session_id)
        //   K2 = HASH(mpint(K) || H || K1)
        // and the truncation/expansion behaviour around it.
        use std::cell::RefCell;
        let seen: RefCell<Vec<Vec<u8>>> = RefCell::new(Vec::new());
        let hash = |data: &[u8]| -> [u8; 32] {
            seen.borrow_mut().push(data.to_vec());
            let n = seen.borrow().len() as u8;
            let mut out = [0u8; 32];
            for (i, b) in out.iter_mut().enumerate() {
                *b = n.wrapping_add(i as u8);
            }
            out
        };
        let k = [0x01u8; 4];
        let h = [0xAAu8; 32];
        let mut out = [0u8; 40]; // > 32 forces one chained expansion
        kdf(hash, &k, &h, b'A', &h, &mut out).expect("derives");
        let calls = seen.borrow().clone();
        assert_eq!(calls.len(), 2, "expected K1 then one expansion block");
        // K1 input: mpint(K) || H || 'A' || session_id — K and H get
        // no length prefix beyond mpint's, session_id is raw (H).
        let mut want = Vec::new();
        want.extend_from_slice(&4u32.to_be_bytes());
        want.extend_from_slice(&k);
        want.extend_from_slice(&h);
        want.push(b'A');
        want.extend_from_slice(&h);
        assert_eq!(calls[0], want, "K1 input");
        // K2 input: mpint(K) || H || K1 (K1 = the first output block).
        let mut want = Vec::new();
        want.extend_from_slice(&4u32.to_be_bytes());
        want.extend_from_slice(&k);
        want.extend_from_slice(&h);
        want.extend_from_slice(&out[..32]);
        assert_eq!(calls[1], want, "K2 input");
        // K2 filled the remainder (40 - 32 = 8 bytes taken).
        assert_eq!(out[..32], {
            let mut b = [0u8; 32];
            for (i, x) in b.iter_mut().enumerate() {
                *x = 1u8.wrapping_add(i as u8);
            }
            b
        });
    }

    #[test]
    fn kdf_refuses_bad_inputs_and_is_deterministic() {
        let k = [1u8; 32];
        let h = [2u8; 32];
        let mut out = [0u8; 32];
        for letter in [b'G', b'a', b'@', 0u8] {
            assert_eq!(
                kdf(sha256, &k, &h, letter, &h, &mut out),
                Err(KdfError::BadLetter),
                "accepted letter {letter}"
            );
        }
        assert_eq!(
            kdf(sha256, &k, &h, b'A', &h, &mut []),
            Err(KdfError::BadLength)
        );
        assert_eq!(
            kdf(sha256, &k, &h, b'A', &h, &mut [0u8; KDF_MAX_OUTPUT + 1]),
            Err(KdfError::BadLength)
        );
        let big = [0u8; 65];
        assert_eq!(
            kdf(sha256, &big, &h, b'A', &h, &mut out),
            Err(KdfError::InputTooLong)
        );
        assert_eq!(
            kdf(sha256, &k, &big, b'A', &h, &mut out),
            Err(KdfError::InputTooLong)
        );
        assert_eq!(
            kdf(sha256, &k, &h, b'A', &big, &mut out),
            Err(KdfError::InputTooLong)
        );
        // Deterministic; distinct per letter.
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        kdf(sha256, &k, &h, b'A', &h, &mut a).expect("derives");
        kdf(sha256, &k, &h, b'A', &h, &mut b).expect("derives");
        assert_eq!(a, b);
        kdf(sha256, &k, &h, b'B', &h, &mut b).expect("derives");
        assert_ne!(a, b);
        // A shorter output is a prefix of a longer one.
        let mut long = [0u8; 40];
        kdf(sha256, &k, &h, b'A', &h, &mut long).expect("derives");
        let mut short = [0u8; 16];
        kdf(sha256, &k, &h, b'A', &h, &mut short).expect("derives");
        assert_eq!(short, long[..16]);
    }

    #[test]
    fn ct_eq_accepts_only_exact_matches() {
        assert!(ct_eq(b"tag", b"tag"));
        assert!(ct_eq(b"", b""));
        assert!(!ct_eq(b"tag", b"tak")); // one flipped bit
        assert!(!ct_eq(b"tag", b"tag2")); // different length
        assert!(!ct_eq(b"", b"x"));
        let mut a = [0x5Au8; TAG_LEN];
        let b = a;
        assert!(ct_eq(&a, &b));
        a[17] ^= 0x01;
        assert!(!ct_eq(&a, &b));
        a[17] ^= 0x01;
        assert!(ct_eq(&a, &b));
    }

    // ---- S2: encrypted packets end to end (real AES + HMAC) -------
    //
    // The dev-dependencies (aes/ctr/hmac/sha2 — the audited crates the
    // kernel uses) make these roundtrips the real thing at a fixed
    // key/IV: seal_packet and EncryptedRx run exactly the code paths
    // the kernel drives against github.com:22, proven live by the
    // smoke's SSH_KEX_OK.

    /// One direction at a fixed key/IV: continuous AES-128-CTR
    /// keystream + HMAC-SHA256, i.e. a `PacketProtector` built from
    /// the same crates as `kernel::ssh::Direction`.
    struct TestDir {
        ctr: Ctr128BE<Aes128>,
        mac_key: [u8; 32],
    }

    impl TestDir {
        fn new() -> Self {
            let key = [0x42u8; 16];
            let iv = [0x24u8; 16];
            Self {
                ctr: Ctr128BE::<Aes128>::new_from_slices(&key, &iv).expect("16-byte key and IV"),
                mac_key: [0x99u8; 32],
            }
        }
    }

    impl PacketProtector for TestDir {
        fn block_size(&self) -> usize {
            ENC_BLOCK
        }
        fn open(&mut self, buf: &mut [u8]) {
            self.ctr.apply_keystream(buf);
        }
        fn seal(&mut self, buf: &mut [u8]) {
            self.ctr.apply_keystream(buf);
        }
        fn tag(&mut self, seq: u32, packet: &[u8]) -> [u8; TAG_LEN] {
            let mut mac = Hmac::<Sha256>::new_from_slice(&self.mac_key).expect("32-byte key");
            mac.update(&seq.to_be_bytes());
            mac.update(packet);
            mac.finalize().into_bytes().into()
        }
    }

    #[test]
    fn seal_packet_roundtrip_with_fixed_key_iv() {
        let mut tx = TestDir::new();
        let mut rx = TestDir::new(); // fresh keystream at the same IV
        let payload = b"\x05\x00\x00\x00\x0cssh-userauth";
        let mut wire = [0u8; 256];
        let n = seal_packet(payload, |p| p.fill(0x77), &mut tx, 7, &mut wire).expect("fits");
        assert_eq!(n % ENC_BLOCK, 0, "ciphertext + tag stay block-aligned");
        // AES-CTR actually ran: the wire bytes are not the plaintext.
        assert_ne!(&wire[5..5 + payload.len()], payload.as_slice());
        // Decrypt with the receiver (CTR keystream is symmetric) and
        // decode exactly like the kernel does.
        let mut buf = wire[..n].to_vec();
        rx.seal(&mut buf[..n - TAG_LEN]);
        match decode_packet_block(&buf[..n - TAG_LEN], ENC_BLOCK) {
            PacketStep::Done {
                consumed,
                payload: got,
            } => {
                assert_eq!(consumed, n - TAG_LEN);
                assert_eq!(got, payload.as_slice());
            }
            other => panic!("decrypted packet does not decode: {other:?}"),
        }
        // The tag in the clear is HMAC(key, seq || plaintext packet).
        let mut mac = Hmac::<Sha256>::new_from_slice(&[0x99u8; 32]).expect("32-byte key");
        mac.update(&7u32.to_be_bytes());
        mac.update(&buf[..n - TAG_LEN]);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(&expected[..], &wire[n - TAG_LEN..n]);
    }

    #[test]
    fn seal_packet_refuses_bit_flips() {
        let mut tx = TestDir::new();
        let payload = b"\x33\x44\x55";
        let mut wire = [0u8; 128];
        let n = seal_packet(payload, |p| p.fill(1), &mut tx, 3, &mut wire).expect("fits");
        let mac_over = |seq: u32, plain: &[u8]| -> [u8; TAG_LEN] {
            let mut mac = Hmac::<Sha256>::new_from_slice(&[0x99u8; 32]).expect("32-byte key");
            mac.update(&seq.to_be_bytes());
            mac.update(plain);
            mac.finalize().into_bytes().into()
        };
        // The untampered plaintext packet (the MAC's input — the wire
        // bytes are ciphertext) and the transmitted tag.
        let plain = {
            let mut rx = TestDir::new();
            let mut b = wire[..n].to_vec();
            rx.seal(&mut b[..n - TAG_LEN]);
            b
        };
        assert!(ct_eq(
            &mac_over(3, &plain[..n - TAG_LEN]),
            &wire[n - TAG_LEN..n]
        ));

        // Flip one ciphertext byte: after decryption the recomputed
        // MAC over the tampered plaintext no longer matches the tag.
        let mut tampered = wire;
        tampered[6] ^= 0x01;
        let mut rx = TestDir::new();
        rx.seal(&mut tampered[..n - TAG_LEN]);
        assert!(
            !ct_eq(
                &mac_over(3, &tampered[..n - TAG_LEN]),
                &tampered[n - TAG_LEN..n]
            ),
            "flipped ciphertext accepted"
        );

        // Flip one tag byte: same refusal, ciphertext untouched.
        let mut tampered = wire;
        tampered[n - 1] ^= 0x01;
        assert!(
            !ct_eq(
                &mac_over(3, &plain[..n - TAG_LEN]),
                &tampered[n - TAG_LEN..n]
            ),
            "flipped tag accepted"
        );
    }

    #[test]
    fn seal_packet_recomputes_padding_for_block_16() {
        // One sender and one receiver in lockstep: the keystream is
        // continuous across packets (RFC4253 §6.3), so each packet's
        // framing is inspected through the matching decryptor.
        let mut tx = TestDir::new();
        let mut rx = TestDir::new();
        let payload = [0x11u8; 40];
        for len in 1..=payload.len() {
            let mut wire = [0u8; 256];
            let n = seal_packet(&payload[..len], |p| p.fill(0xEE), &mut tx, 0, &mut wire)
                .expect("fits");
            let total = n - TAG_LEN;
            assert_eq!(total % ENC_BLOCK, 0, "len {len}");
            let mut plain = wire[..n].to_vec();
            rx.seal(&mut plain[..total]);
            assert!(plain[4] >= MIN_PADDING as u8, "len {len}");
            assert_eq!(total, 4 + 1 + len + usize::from(plain[4]), "len {len}");
        }
        // Refuses to overflow its output (never a panic).
        let mut wire = [0u8; 32];
        assert_eq!(
            seal_packet(&payload, |p| p.fill(0), &mut tx, 0, &mut wire),
            None
        );
    }

    #[test]
    fn encrypted_rx_reassembles_chunked_packets() {
        let mut tx = TestDir::new();
        let mut rx_prot = TestDir::new();
        let payload = b"\x06\x00\x00\x00\x0cssh-userauth";
        let mut wire = [0u8; 256];
        let n = seal_packet(payload, |p| p.fill(9), &mut tx, 4, &mut wire).expect("fits");

        let mut buf = [0u8; 512];
        let mut erx = EncryptedRx::new(&mut buf, 0);
        // One byte at a time: every smoltcp read split must be
        // tolerated, and no early byte may surface a payload.
        for (i, byte) in wire[..n].iter().enumerate() {
            erx.push(&[*byte]).expect("space");
            let got = erx.next(&mut rx_prot, 4).expect("no refusal");
            if i + 1 < n {
                assert_eq!(got, None, "packet complete early at byte {i}");
            } else {
                let (s, e) = got.expect("complete at the last byte");
                assert_eq!(&erx.bytes()[s..e], payload.as_slice());
                erx.consume();
            }
        }
        // Buffer drained: nothing more, no refusal.
        assert_eq!(erx.next(&mut rx_prot, 4).expect("no refusal"), None);
        // spare() refuses once the buffer is full — the read loop can
        // never grow it.
        let mut small = [0u8; 4];
        let mut erx = EncryptedRx::new(&mut small, 4);
        assert_eq!(erx.spare().map(|_| ()), Err(OpenError::Full));
        assert_eq!(erx.push(&[0; 5]), Err(OpenError::Full));
    }

    #[test]
    fn encrypted_rx_handles_pipelined_packets() {
        let mut tx = TestDir::new();
        let mut rx_prot = TestDir::new();
        let p1: &[u8] = b"\x07\x00\x00\x00\x00"; // EXT_INFO, zero entries
        let p2: &[u8] = b"\x06\x00\x00\x00\x0cssh-userauth";
        let mut w1 = [0u8; 128];
        let n1 = seal_packet(p1, |p| p.fill(1), &mut tx, 0, &mut w1).expect("fits");
        let mut w2 = [0u8; 128];
        let n2 = seal_packet(p2, |p| p.fill(2), &mut tx, 1, &mut w2).expect("fits");

        let mut buf = [0u8; 512];
        buf[..n1].copy_from_slice(&w1[..n1]);
        buf[n1..n1 + n2].copy_from_slice(&w2[..n2]);
        // `initial` models ciphertext that arrived pipelined behind
        // the plaintext SSH_MSG_NEWKEYS.
        let mut erx = EncryptedRx::new(&mut buf, n1 + n2);
        let (s, e) = erx
            .next(&mut rx_prot, 0)
            .expect("no refusal")
            .expect("first packet complete");
        assert_eq!(&erx.bytes()[s..e], p1);
        // Deliberately *not* consuming: the next call must apply the
        // pending shift itself, so a skipped consume cannot desync.
        let (s, e) = erx
            .next(&mut rx_prot, 1)
            .expect("no refusal")
            .expect("second packet complete");
        assert_eq!(&erx.bytes()[s..e], p2);
        erx.consume();
        assert_eq!(erx.next(&mut rx_prot, 2).expect("no refusal"), None);
    }

    #[test]
    fn encrypted_rx_refuses_bad_tags_lengths_and_padding() {
        let payload: &[u8] = b"\x06\x00\x00\x00\x0cssh-userauth";
        let mut wire = [0u8; 256];
        let n = {
            let mut tx = TestDir::new();
            seal_packet(payload, |p| p.fill(3), &mut tx, 5, &mut wire).expect("fits")
        };

        // A flipped tag byte → MacMismatch; the payload never surfaces.
        let mut bad = wire;
        bad[n - 1] ^= 0x80;
        let mut buf = [0u8; 512];
        let mut erx = EncryptedRx::new(&mut buf, 0);
        erx.push(&bad[..n]).expect("space");
        let mut rx_prot = TestDir::new();
        assert_eq!(erx.next(&mut rx_prot, 5), Err(OpenError::MacMismatch));

        // A flipped ciphertext byte → the recomputed MAC misses too.
        let mut bad = wire;
        bad[9] ^= 0x01;
        let mut erx = EncryptedRx::new(&mut buf, 0);
        erx.push(&bad[..n]).expect("space");
        let mut rx_prot = TestDir::new();
        assert_eq!(erx.next(&mut rx_prot, 5), Err(OpenError::MacMismatch));

        // A hostile declared length is refused from the four decrypted
        // header bytes — TooLarge, before any body is waited on.
        for hostile in [35_004u32, 3_996u32] {
            let mut sealer = TestDir::new();
            let mut head = [0u8; 16];
            head[..4].copy_from_slice(&hostile.to_be_bytes());
            head[4] = 4;
            sealer.seal(&mut head);
            let mut opener = TestDir::new();
            let mut erx = EncryptedRx::new(&mut buf, 0);
            erx.push(&head).expect("space");
            let want = if hostile > MAX_PACKET_LENGTH {
                // Above the RFC4253 §6.1 cap: refused by packet_total.
                OpenError::Packet(PacketError::TooLarge)
            } else {
                // Legal length but larger than the fixed buffer.
                OpenError::TooLarge
            };
            assert_eq!(erx.next(&mut opener, 5), Err(want), "pl {hostile}");
        }

        // Defense in depth: a MAC-valid packet (we hold the key) with
        // an illegal padding_length is still refused by the framing.
        let mut pkt = [0u8; 16];
        pkt[..4].copy_from_slice(&12u32.to_be_bytes()); // total 16, 16-aligned
        pkt[4] = 3; // padding_length below MIN_PADDING
        pkt[5] = 0x06;
        let mut mac_dir = TestDir::new();
        let tag = mac_dir.tag(9, &pkt);
        let mut sealer = TestDir::new();
        sealer.seal(&mut pkt);
        let mut wire = [0u8; 48];
        wire[..16].copy_from_slice(&pkt);
        wire[16..].copy_from_slice(&tag);
        let mut opener = TestDir::new();
        let mut erx = EncryptedRx::new(&mut buf, 0);
        erx.push(&wire).expect("space");
        assert_eq!(
            erx.next(&mut opener, 9),
            Err(OpenError::Packet(PacketError::BadPadding))
        );
    }

    // ---- S3: `publickey` auth with ssh-ed25519 (RFC4252 §7) --------
    //
    // Fixtures are **public halves only**: a key generated for this
    // test with `ssh-keygen -t ed25519` (its private half was never
    // written anywhere), and github.com's published host key (docs
    // §B.3), whose SHA-256 fingerprint GitHub publishes too.

    /// Raw public key of the fixture.
    const FIXTURE_KEY: [u8; 32] = [
        0x5c, 0xfb, 0x6c, 0x8f, 0x65, 0x5a, 0x9f, 0xe5, 0x97, 0xed, 0x0a, 0xd2, 0x6e, 0xde, 0xb8,
        0x5d, 0x2b, 0xc8, 0xde, 0x8c, 0x4d, 0x04, 0x8b, 0x9a, 0x39, 0x38, 0x3a, 0xee, 0xeb, 0x38,
        0x80, 0xfb,
    ];
    /// The blob exactly as `ssh-keygen` emitted it (`base64 -d` of the
    /// second field of the `.pub` line).
    const FIXTURE_BLOB_HEX: &str = "0000000b7373682d65643235353139000000205cfb6c8f655a9fe597ed0ad26edeb85d2bc8de8c4d048b9a39383aeeeb3880fb";
    /// The `.pub` line's base64 field — what `ssh-keygen`/OpenSSH
    /// produce for the same blob.
    const FIXTURE_PUB_B64: &str =
        "AAAAC3NzaC1lZDI1NTE5AAAAIFz7bI9lWp/ll+0K0m7euF0ryN6MTQSLmjk4Ou7rOID7";
    /// `ssh-keygen -lf` of the fixture.
    const FIXTURE_FP: &str = "SHA256:my/l9XnZ33YrPKCJsTEFShnLr03wDFkAc+6LWph2CwI";

    /// github.com's ed25519 host key (S2's pin).
    const GITHUB_KEY: [u8; 32] = [
        0xe3, 0x2a, 0xaa, 0x79, 0x15, 0xce, 0xb9, 0xb4, 0x49, 0xd1, 0xba, 0x50, 0xea, 0x2a, 0x28,
        0xbb, 0x1a, 0x6e, 0x01, 0xf9, 0x0b, 0xda, 0x24, 0x5a, 0x2d, 0x1d, 0x87, 0x69, 0x7d, 0x18,
        0xa2, 0x65,
    ];
    /// The fingerprint on GitHub's published fingerprints page.
    const GITHUB_FP: &str = "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU";

    fn unhex(s: &str) -> Vec<u8> {
        let bytes = s.as_bytes();
        assert!(bytes.len().is_multiple_of(2), "odd hex fixture");
        let (pairs, _tail) = bytes.as_chunks::<2>();
        let mut v = Vec::new();
        for pair in pairs {
            let hi = (pair[0] as char).to_digit(16).expect("hex") as u8;
            let lo = (pair[1] as char).to_digit(16).expect("hex") as u8;
            v.push((hi << 4) | lo);
        }
        v
    }

    fn fixture_blob() -> [u8; ED25519_KEY_BLOB_LEN] {
        let mut blob = [0u8; ED25519_KEY_BLOB_LEN];
        assert_eq!(
            ed25519_key_blob(&FIXTURE_KEY, &mut blob),
            Some(ED25519_KEY_BLOB_LEN)
        );
        blob
    }

    /// Hand-built `SSH_MSG_USERAUTH_REQUEST`/`publickey` bytes, field by
    /// field, independent of the encoder under test.
    fn publickey_request_wire(key_blob: &[u8], signature: Option<&[u8]>) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(SSH_MSG_USERAUTH_REQUEST);
        v.extend_from_slice(&3u32.to_be_bytes());
        v.extend_from_slice(b"git");
        v.extend_from_slice(&14u32.to_be_bytes());
        v.extend_from_slice(b"ssh-connection");
        v.extend_from_slice(&9u32.to_be_bytes());
        v.extend_from_slice(b"publickey");
        v.push(u8::from(signature.is_some()));
        v.extend_from_slice(&11u32.to_be_bytes());
        v.extend_from_slice(b"ssh-ed25519");
        v.extend_from_slice(&(key_blob.len() as u32).to_be_bytes());
        v.extend_from_slice(key_blob);
        if let Some(sig) = signature {
            v.extend_from_slice(&(sig.len() as u32).to_be_bytes());
            v.extend_from_slice(sig);
        }
        v
    }

    #[test]
    fn ed25519_key_blob_matches_the_ssh_keygen_fixture() {
        let blob = fixture_blob();
        assert_eq!(blob.as_slice(), unhex(FIXTURE_BLOB_HEX).as_slice());
        // ...and it is what OpenSSH base64s into a `.pub` line.
        let mut b64 = [0u8; 96];
        let n = base64_encode(&blob, true, &mut b64).expect("fits");
        assert_eq!(&b64[..n], FIXTURE_PUB_B64.as_bytes());
        // Parsing it back yields the key, byte for byte.
        assert_eq!(parse_ed25519_key_blob(&blob), Ok(FIXTURE_KEY));
    }

    #[test]
    fn ed25519_key_blob_layout_is_string_string() {
        assert_eq!(ED25519_KEY_BLOB_LEN, 4 + 11 + 4 + 32);
        let blob = fixture_blob();
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..], &FIXTURE_KEY);
    }

    #[test]
    fn fingerprints_match_ssh_keygen_and_githubs_published_page() {
        let mut text = [0u8; FINGERPRINT_LEN];
        let n = write_fingerprint(&sha256(&fixture_blob()), &mut text).expect("fits");
        assert_eq!(n, FINGERPRINT_LEN);
        assert_eq!(&text[..n], FIXTURE_FP.as_bytes());

        let mut github = [0u8; ED25519_KEY_BLOB_LEN];
        assert_eq!(
            ed25519_key_blob(&GITHUB_KEY, &mut github),
            Some(ED25519_KEY_BLOB_LEN)
        );
        let n = write_fingerprint(&sha256(&github), &mut text).expect("fits");
        assert_eq!(&text[..n], GITHUB_FP.as_bytes());
    }

    #[test]
    fn ed25519_signature_blob_layout_and_roundtrip() {
        assert_eq!(ED25519_SIG_BLOB_LEN, 4 + 11 + 4 + 64);
        let sig: [u8; 64] = core::array::from_fn(|i| i as u8);
        let mut blob = [0u8; ED25519_SIG_BLOB_LEN];
        assert_eq!(ed25519_signature_blob(&sig, &mut blob), Some(83));
        assert_eq!(&blob[..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &64u32.to_be_bytes());
        assert_eq!(parse_ed25519_signature_blob(&blob), Ok(sig));
        // A key blob is not a signature blob and vice versa (length).
        assert_eq!(
            parse_ed25519_signature_blob(&fixture_blob()),
            Err(KeyError::BadLength)
        );
        assert_eq!(parse_ed25519_key_blob(&blob), Err(KeyError::BadLength));
    }

    #[test]
    fn blob_parsers_refuse_every_truncation() {
        let key = fixture_blob();
        let mut sig = [0u8; ED25519_SIG_BLOB_LEN];
        assert_eq!(ed25519_signature_blob(&[7; 64], &mut sig), Some(83));
        for cut in 0..key.len() {
            assert!(
                parse_ed25519_key_blob(&key[..cut]).is_err(),
                "key blob truncation {cut} accepted"
            );
        }
        for cut in 0..sig.len() {
            assert!(
                parse_ed25519_signature_blob(&sig[..cut]).is_err(),
                "sig blob truncation {cut} accepted"
            );
        }
        // One byte past the end is trailing garbage, not tolerance.
        let mut long = key.to_vec();
        long.push(0);
        assert_eq!(
            parse_ed25519_key_blob(&long),
            Err(KeyError::TrailingGarbage)
        );
    }

    #[test]
    fn blob_parsers_refuse_foreign_algorithms_and_lengths() {
        // Same shape, wrong algorithm name (an RSA key would be this
        // shape) — refused before any byte could be used.
        let mut rsa = vec![0u8; 4 + 7 + 4 + 32];
        rsa[..4].copy_from_slice(&7u32.to_be_bytes());
        rsa[4..11].copy_from_slice(b"ssh-rsa");
        rsa[11..15].copy_from_slice(&32u32.to_be_bytes());
        assert_eq!(parse_ed25519_key_blob(&rsa), Err(KeyError::WrongAlgorithm));

        // Right algorithm, wrong body length (31 and 33).
        for len in [31u32, 33] {
            let mut b = vec![0u8; 4 + 11 + 4 + len as usize];
            b[..4].copy_from_slice(&11u32.to_be_bytes());
            b[4..15].copy_from_slice(b"ssh-ed25519");
            b[15..19].copy_from_slice(&len.to_be_bytes());
            assert_eq!(parse_ed25519_key_blob(&b), Err(KeyError::BadLength));
        }

        // A length field claiming far more than the blob holds is
        // refused by the length check itself (never "read what is
        // there").
        let mut lying = fixture_blob().to_vec();
        lying[15..19].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_ed25519_key_blob(&lying), Err(KeyError::BadLength));
    }

    #[test]
    fn key_and_signature_encoders_refuse_short_buffers() {
        let mut out = [0u8; ED25519_KEY_BLOB_LEN];
        assert_eq!(ed25519_key_blob(&FIXTURE_KEY, &mut out[..50]), None);
        assert_eq!(
            ed25519_key_blob(&FIXTURE_KEY, &mut out[..ED25519_KEY_BLOB_LEN]),
            Some(51)
        );
        let mut sig = [0u8; ED25519_SIG_BLOB_LEN];
        assert_eq!(ed25519_signature_blob(&[0; 64], &mut sig[..82]), None);
        assert_eq!(
            ed25519_signature_blob(&[0; 64], &mut sig[..ED25519_SIG_BLOB_LEN]),
            Some(83)
        );
    }

    #[test]
    fn userauth_publickey_probe_has_exact_wire_shape() {
        let blob = fixture_blob();
        let mut out = [0u8; 256];
        let n = userauth_publickey_payload(AUTH_USER, &blob, None, &mut out).expect("fits");
        assert_eq!(n, 110);
        assert_eq!(&out[..n], publickey_request_wire(&blob, None).as_slice());
        // The boolean is FALSE: a probe, not a claim.
        assert_eq!(out[1 + 7 + 18 + 13], 0);
    }

    #[test]
    fn userauth_publickey_signed_request_appends_the_signature() {
        let blob = fixture_blob();
        let mut sig_blob = [0u8; ED25519_SIG_BLOB_LEN];
        assert_eq!(ed25519_signature_blob(&[0xAB; 64], &mut sig_blob), Some(83));
        let mut out = [0u8; 256];
        let n =
            userauth_publickey_payload(AUTH_USER, &blob, Some(&sig_blob), &mut out).expect("fits");
        assert_eq!(n, 110 + 4 + 83);
        assert_eq!(
            &out[..n],
            publickey_request_wire(&blob, Some(&sig_blob)).as_slice()
        );
        assert_eq!(out[1 + 7 + 18 + 13], 1);
    }

    #[test]
    fn userauth_publickey_refuses_bad_inputs() {
        let blob = fixture_blob();
        let mut out = [0u8; 256];
        // No user, no key.
        assert_eq!(userauth_publickey_payload(b"", &blob, None, &mut out), None);
        assert_eq!(
            userauth_publickey_payload(AUTH_USER, b"", None, &mut out),
            None
        );
        // A blob that is not an ed25519 key (wrong alg, trailing junk,
        // wrong length).
        let mut rsa = blob;
        rsa[4..15].copy_from_slice(b"ssh-ed25519"); // keep shape
        rsa[11] = b'X'; // now "ssh-ed2X519"
        assert_eq!(
            userauth_publickey_payload(AUTH_USER, &rsa, None, &mut out),
            None
        );
        let mut long = blob.to_vec();
        long.push(0);
        assert_eq!(
            userauth_publickey_payload(AUTH_USER, &long, None, &mut out),
            None
        );
        // A signature blob that is not 64 bytes of ed25519 signature.
        let mut short = [0u8; ED25519_SIG_BLOB_LEN];
        assert!(ed25519_signature_blob(&[0; 64], &mut short).is_some());
        short[15..19].copy_from_slice(&63u32.to_be_bytes());
        assert_eq!(
            userauth_publickey_payload(AUTH_USER, &blob, Some(&short), &mut out),
            None
        );
        // Output buffer one byte short of the exact request.
        let mut tight = [0u8; 197];
        assert_eq!(
            userauth_publickey_payload(AUTH_USER, &blob, Some(&short), &mut tight[..196]),
            None
        );
        // A hostile user name that would not fit the buffer.
        let big = vec![b'u'; 4096];
        assert_eq!(
            userauth_publickey_payload(&big, &blob, None, &mut out),
            None
        );
    }

    #[test]
    fn signed_data_length_prefixes_the_session_id_before_the_probe() {
        let blob = fixture_blob();
        let mut probe = [0u8; 256];
        let plen = userauth_publickey_payload(AUTH_USER, &blob, None, &mut probe).expect("fits");
        let session = [0x5Au8; 32];
        let mut data = [0u8; 256];
        let dlen = userauth_signed_data(&session, &probe[..plen], &mut data).expect("fits");
        // RFC4252 §7's first field is `string session identifier` —
        // uint32 length ‖ bytes (RFC4251 §5), then the signed request.
        assert_eq!(dlen, 4 + 32 + 110);
        assert_eq!(&data[..4], &32u32.to_be_bytes());
        assert_eq!(&data[4..36], &session);
        assert_eq!(&data[36..dlen], &probe[..plen]);
        // No session id, no request, or a short buffer: refused.
        assert_eq!(userauth_signed_data(b"", &probe[..plen], &mut data), None);
        assert_eq!(userauth_signed_data(&session, b"", &mut data), None);
        assert_eq!(
            userauth_signed_data(&session, &probe[..plen], &mut data[..145]),
            None
        );
    }

    #[test]
    fn signed_request_verifies_and_any_edit_is_rejected() {
        use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

        let sk = SigningKey::from_bytes(&[0x42u8; 32]);
        let vk = sk.verifying_key();
        let mut key_blob = [0u8; ED25519_KEY_BLOB_LEN];
        assert_eq!(
            ed25519_key_blob(&vk.to_bytes(), &mut key_blob),
            Some(ED25519_KEY_BLOB_LEN)
        );

        let mut probe = [0u8; 256];
        let plen =
            userauth_publickey_payload(AUTH_USER, &key_blob, None, &mut probe).expect("fits");
        let session = [0x11u8; 32];
        let mut data = [0u8; 256];
        let dlen = userauth_signed_data(&session, &probe[..plen], &mut data).expect("fits");

        let sig = sk.sign(&data[..dlen]);
        let mut sig_blob = [0u8; ED25519_SIG_BLOB_LEN];
        assert_eq!(
            ed25519_signature_blob(&sig.to_bytes(), &mut sig_blob),
            Some(ED25519_SIG_BLOB_LEN)
        );
        // The blob on the wire roundtrips to the same signature.
        let parsed = parse_ed25519_signature_blob(&sig_blob).expect("our own blob parses");
        assert!(
            vk.verify(&data[..dlen], &Signature::from_bytes(&parsed))
                .is_ok()
        );

        // A different session identifier (rekey / MITM) breaks it.
        let mut other_session = session;
        other_session[31] ^= 1;
        let mut other_data = [0u8; 256];
        let olen =
            userauth_signed_data(&other_session, &probe[..plen], &mut other_data).expect("fits");
        assert!(
            vk.verify(&other_data[..olen], &Signature::from_bytes(&parsed))
                .is_err()
        );

        // So does one flipped bit anywhere in the request itself
        // (byte 4+32 = past the length-prefixed session id).
        for i in [0usize, 1 + 7 + 18 + 13, plen - 1] {
            let mut tampered = data;
            tampered[4 + 32 + i] ^= 1;
            assert!(
                vk.verify(&tampered[..dlen], &Signature::from_bytes(&parsed))
                    .is_err(),
                "tampering at request byte {i} still verified"
            );
        }
    }

    #[test]
    fn pk_ok_roundtrip_and_rejections() {
        let blob = fixture_blob();
        let mut p = Vec::new();
        p.push(SSH_MSG_USERAUTH_PK_OK);
        p.extend_from_slice(&11u32.to_be_bytes());
        p.extend_from_slice(b"ssh-ed25519");
        p.extend_from_slice(&(blob.len() as u32).to_be_bytes());
        p.extend_from_slice(&blob);
        let ok = parse_userauth_pk_ok(&p).expect("parses");
        assert_eq!(ok.algorithm, b"ssh-ed25519");
        assert_eq!(ok.key_blob, &blob);

        // Wrong message byte.
        let mut wrong = p.clone();
        wrong[0] = SSH_MSG_USERAUTH_FAILURE;
        assert_eq!(
            parse_userauth_pk_ok(&wrong),
            Err(UserAuthError::WrongMessage)
        );
        // Wrong algorithm name (same length, so the algorithm is what
        // gets refused, not the field length).
        let mut alg = p.clone();
        alg[5..16].copy_from_slice(b"ssh-ed2551X");
        assert_eq!(
            parse_userauth_pk_ok(&alg),
            Err(UserAuthError::WrongAlgorithm)
        );
        // A key blob that is not an ed25519 key (the echoed blob's
        // inner algorithm byte is corrupted — still 51 bytes, so the
        // length checks pass and the blob check must refuse it).
        let mut badkey = p.clone();
        badkey[24] = b'X';
        assert_eq!(parse_userauth_pk_ok(&badkey), Err(UserAuthError::BadKey));
        // Trailing bytes and every truncation.
        let mut tail = p.clone();
        tail.push(0);
        assert_eq!(
            parse_userauth_pk_ok(&tail),
            Err(UserAuthError::TrailingGarbage)
        );
        for cut in 0..p.len() {
            assert!(
                parse_userauth_pk_ok(&p[..cut]).is_err(),
                "pk_ok truncation {cut} accepted"
            );
        }
    }

    #[test]
    fn userauth_success_and_banner_shapes() {
        assert_eq!(parse_userauth_success(&[SSH_MSG_USERAUTH_SUCCESS]), Ok(()));
        assert_eq!(
            parse_userauth_success(&[SSH_MSG_USERAUTH_SUCCESS, 0]),
            Err(UserAuthError::TrailingGarbage)
        );
        assert_eq!(
            parse_userauth_success(&[SSH_MSG_USERAUTH_FAILURE]),
            Err(UserAuthError::WrongMessage)
        );
        assert_eq!(parse_userauth_success(&[]), Err(UserAuthError::Truncated));

        let mut b = Vec::new();
        b.push(SSH_MSG_USERAUTH_BANNER);
        b.extend_from_slice(&14u32.to_be_bytes());
        b.extend_from_slice(b"hello, friend\n");
        b.extend_from_slice(&0u32.to_be_bytes());
        let banner = parse_userauth_banner(&b).expect("parses");
        assert_eq!(banner.message, b"hello, friend\n");
        assert_eq!(banner.language, b"");
        for cut in 0..b.len() {
            assert!(
                parse_userauth_banner(&b[..cut]).is_err(),
                "banner truncation {cut} accepted"
            );
        }
        let mut tail = b.clone();
        tail.push(1);
        assert_eq!(
            parse_userauth_banner(&tail),
            Err(UserAuthError::TrailingGarbage)
        );
        // A length field that overruns the payload.
        let mut liar = b.clone();
        liar[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_userauth_banner(&liar), Err(UserAuthError::Truncated));
    }

    #[test]
    fn seed_hex_accepts_both_cases_and_surrounding_whitespace() {
        let mut seed = [0u8; 32];
        parse_seed_hex(
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            &mut seed,
        )
        .expect("lowercase");
        assert_eq!(seed, core::array::from_fn(|i| i as u8));
        parse_seed_hex(
            b"  \r\n000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F\t\n",
            &mut seed,
        )
        .expect("uppercase + whitespace");
        assert_eq!(seed, core::array::from_fn(|i| i as u8));
        // Trimmed to nothing is a length error, not an empty seed.
        assert_eq!(
            parse_seed_hex(b"  \n\t ", &mut seed),
            Err(KeyError::BadHexLength)
        );
    }

    #[test]
    fn seed_hex_refuses_malformed_text() {
        let mut seed = [0u8; 32];
        // 63 and 65 digits.
        assert_eq!(
            parse_seed_hex(&[b'a'; 63], &mut seed),
            Err(KeyError::BadHexLength)
        );
        assert_eq!(
            parse_seed_hex(&[b'a'; 65], &mut seed),
            Err(KeyError::BadHexLength)
        );
        // A non-hex byte in either nibble position, and an interior
        // space (whitespace is only trimmed at the ends).
        for pos in [0usize, 1, 32, 63] {
            for bad_byte in *b"g:" {
                let mut b = vec![b'0'; 64];
                b[pos] = bad_byte;
                assert_eq!(
                    parse_seed_hex(&b, &mut seed),
                    Err(KeyError::NotHex),
                    "byte {pos} set to {bad_byte}"
                );
            }
            if (1..63).contains(&pos) {
                let mut b = vec![b'0'; 64];
                b[pos] = b' ';
                assert_eq!(parse_seed_hex(&b, &mut seed), Err(KeyError::NotHex));
            }
        }
        // A trailing non-hex digit is still 64 bytes long, so it is the
        // digit check (not the length check) that must catch it.
        let mut tail = vec![b'0'; 63];
        tail.push(b'z');
        assert_eq!(parse_seed_hex(&tail, &mut seed), Err(KeyError::NotHex));
        // A 32-byte raw binary seed is not hex text.
        assert!(parse_seed_hex(&[0x7f; 32], &mut seed).is_err());
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        // RFC4648 §10 test vectors.
        let cases: [(&[u8], &str, &str); 7] = [
            (b"", "", ""),
            (b"f", "Zg==", "Zg"),
            (b"fo", "Zm8=", "Zm8"),
            (b"foo", "Zm9v", "Zm9v"),
            (b"foob", "Zm9vYg==", "Zm9vYg"),
            (b"fooba", "Zm9vYmE=", "Zm9vYmE"),
            (b"foobar", "Zm9vYmFy", "Zm9vYmFy"),
        ];
        let mut out = [0u8; 32];
        for (input, padded, unpadded) in cases {
            let n = base64_encode(input, true, &mut out).expect("fits");
            assert_eq!(&out[..n], padded.as_bytes(), "padded {padded}");
            let n = base64_encode(input, false, &mut out).expect("fits");
            assert_eq!(&out[..n], unpadded.as_bytes(), "unpadded {unpadded}");
        }
    }

    #[test]
    fn base64_and_fingerprint_refuse_short_buffers() {
        let mut out = [0u8; 8];
        // 6 bytes → 8 padded chars, 8 chars unpadded; one less fails.
        for (input_len, padded_len, unpadded_len) in
            [(6usize, 8usize, 8usize), (4, 8, 6), (1, 4, 2)]
        {
            let input = vec![0u8; input_len];
            assert_eq!(
                base64_encode(&input, true, &mut out[..padded_len - 1]),
                None
            );
            assert_eq!(
                base64_encode(&input, true, &mut out[..padded_len]),
                Some(padded_len)
            );
            assert_eq!(
                base64_encode(&input, false, &mut out[..unpadded_len - 1]),
                None
            );
            assert_eq!(
                base64_encode(&input, false, &mut out[..unpadded_len]),
                Some(unpadded_len)
            );
        }
        let mut fp = [0u8; FINGERPRINT_LEN];
        assert_eq!(
            write_fingerprint(&[0; 32], &mut fp[..FINGERPRINT_LEN - 1]),
            None
        );
        assert_eq!(
            write_fingerprint(&[0; 32], &mut fp[..FINGERPRINT_LEN]),
            Some(FINGERPRINT_LEN)
        );
        assert_eq!(&fp[..7], b"SHA256:");
    }

    // ---- S5: server-side glue ------------------------------------

    /// A valid `ssh-ed25519` key blob for `seed` (any 32 bytes are a
    /// syntactically valid ed25519 public key here — only the blob
    /// shape is under test).
    fn key_blob_for(seed: u8) -> Vec<u8> {
        let mut blob = [0u8; ED25519_KEY_BLOB_LEN];
        let n = ed25519_key_blob(&[seed; ED25519_KEY_LEN], &mut blob).expect("blob fits");
        assert_eq!(n, ED25519_KEY_BLOB_LEN);
        blob.to_vec()
    }

    #[test]
    fn server_kexinit_is_a_legal_responder_packet() {
        let mut wire = [0u8; KEXINIT_WIRE_MAX];
        let n = encode_kexinit_server(&[0x5A; 16], &mut wire).expect("fits");
        let payload = match decode_packet(&wire[..n]) {
            PacketStep::Done { payload, .. } => payload,
            other => panic!("server KEXINIT does not decode: {other:?}"),
        };
        let server = parse_kexinit(payload).expect("parses");
        assert_eq!(server.cookie, &[0x5A; 16]);
        assert!(namelist_contains(
            server.kex_algorithms,
            b"curve25519-sha256"
        ));
        // A responder must not advertise the client-only signal.
        assert!(!namelist_contains(server.kex_algorithms, b"ext-info-c"));
        assert!(!namelist_contains(server.kex_algorithms, b"ext-info-s"));
        assert_eq!(server.server_host_key_algorithms, b"ssh-ed25519");
        assert_eq!(server.encryption_algorithms_c2s, b"aes128-ctr");
        assert_eq!(server.encryption_algorithms_s2c, b"aes128-ctr");
        assert_eq!(server.mac_algorithms_c2s, b"hmac-sha2-256");
        assert_eq!(server.compression_algorithms_c2s, b"none");
        assert_eq!(server.language_c2s, b"");
        assert!(!server.first_kex_packet_follows);
    }

    #[test]
    fn server_intersection_takes_the_clients_first_choice() {
        // The client's ordering decides (RFC4253 §7.1) among the
        // names the server also lists; the server's list is the
        // selection set. aes128 is the only cipher we implement.
        let lists = [
            b"curve25519-sha256,ext-info-c".as_slice(),
            b"ssh-ed25519",
            b"aes256-ctr,aes128-ctr",
            b"aes128-ctr,aes256-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ];
        let p = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let client = parse_kexinit(&p).expect("parses");
        let n = intersect_as_server(&client);
        assert_eq!(
            n,
            Negotiated {
                kex: Some("curve25519-sha256"),
                host_key: Some("ssh-ed25519"),
                enc_c2s: Some("aes128-ctr"),
                enc_s2c: Some("aes128-ctr"),
                mac_c2s: Some("hmac-sha2-256"),
                mac_s2c: Some("hmac-sha2-256"),
                comp_c2s: Some("none"),
                comp_s2c: Some("none"),
            }
        );
        assert_eq!(check_must_have(&n), Ok(()));

        // A client without curve25519: no agreement, and the gate says
        // which field failed.
        let lists = [
            b"diffie-hellman-group14-sha256".as_slice(),
            b"ssh-ed25519",
            b"aes128-ctr",
            b"aes128-ctr",
            b"hmac-sha2-256",
            b"hmac-sha2-256",
            b"none",
            b"none",
            b"",
            b"",
        ];
        let p = payload(lists, 0, 0, SSH_MSG_KEXINIT);
        let client = parse_kexinit(&p).expect("parses");
        let n = intersect_as_server(&client);
        assert_eq!(n.kex, None);
        assert_eq!(check_must_have(&n), Err(Missing::Kex));
    }

    #[test]
    fn kexdh_init_and_reply_roundtrip() {
        let mut init = [0u8; 64];
        let n = kexdh_init_payload(&[7u8; 32], &mut init).expect("fits");
        assert_eq!(parse_kexdh_init(&init[..n]), Ok([7u8; 32]));

        // All-zero e is a small-order point: refused.
        let mut zero = [0u8; 64];
        let n = kexdh_init_payload(&[0u8; 32], &mut zero).expect("fits");
        assert_eq!(parse_kexdh_init(&zero[..n]), Err(KexDhError::ZeroPublicKey));
        // Wrong length, wrong message, trailing garbage.
        assert_eq!(
            parse_kexdh_init(&[SSH_MSG_KEXDH_INIT, 0, 0, 0, 31]),
            Err(KexDhError::BadPublicKey)
        );
        assert_eq!(
            parse_kexdh_init(&[SSH_MSG_KEXDH_REPLY]),
            Err(KexDhError::WrongMessage)
        );

        let host = key_blob_for(0x11);
        let sig = {
            let mut s = [0u8; ED25519_SIG_BLOB_LEN];
            let n = ed25519_signature_blob(&[0x22; 64], &mut s).expect("fits");
            assert_eq!(n, ED25519_SIG_BLOB_LEN);
            s.to_vec()
        };
        // `kexdh_reply_payload` above is the encoder under test; the
        // test module's helper of the same name builds the *bytes*
        // independently, and the two must agree.
        let mut wire = [0u8; 256];
        let n = crate::kexdh_reply_payload(&host, &[9u8; 32], &sig, &mut wire).expect("fits");
        assert_eq!(
            &wire[..n],
            &kexdh_reply_payload(&host, &[9u8; 32], &sig)[..]
        );
        let parsed = parse_kexdh_reply(&wire[..n]).expect("parses");
        assert_eq!(parsed.host_key, &host[..]);
        assert_eq!(parsed.f, &[9u8; 32]);
        assert_eq!(parsed.signature, &sig[..]);
    }

    #[test]
    fn server_encode_of_auth_answers_matches_the_client_parsers() {
        let mut buf = [0u8; 256];
        let n = userauth_failure_payload(b"publickey", false, &mut buf).expect("fits");
        let f = parse_userauth_failure(&buf[..n]).expect("parses");
        assert_eq!(f.methods, b"publickey");
        assert!(!f.partial_success);

        let n = userauth_success_payload(&mut buf).expect("fits");
        assert_eq!(n, 1);
        assert_eq!(parse_userauth_success(&buf[..n]), Ok(()));

        let blob = key_blob_for(0x33);
        let n = userauth_pk_ok_payload(&blob, &mut buf).expect("fits");
        let ok = parse_userauth_pk_ok(&buf[..n]).expect("parses");
        assert_eq!(ok.algorithm, ED25519);
        assert_eq!(ok.key_blob, &blob[..]);

        let n = service_accept_payload(b"ssh-userauth", &mut buf).expect("fits");
        assert_eq!(parse_service_accept(&buf[..n]), Ok(&b"ssh-userauth"[..]));
        assert_eq!(
            parse_service_accept(&buf[..n]).expect("parses"),
            b"ssh-userauth"
        );
    }

    #[test]
    fn auth_request_parses_probe_signed_and_none() {
        let blob = key_blob_for(0x44);
        let mut buf = [0u8; 512];
        // Probe.
        let n = userauth_publickey_payload(AUTH_USER, &blob, None, &mut buf).expect("fits");
        let req = parse_userauth_request(&buf[..n]).expect("probe parses");
        assert_eq!(req.user, AUTH_USER);
        assert_eq!(req.service, AUTH_SERVICE);
        assert_eq!(req.method, AUTH_METHOD_PUBLICKEY);
        assert!(!req.has_signature);
        assert_eq!(req.algorithm, ED25519);
        assert_eq!(req.key_blob, &blob[..]);
        assert!(req.signature.is_empty());

        // The probe must be kept: the signed request overwrites `buf`.
        let probe = buf[..n].to_vec();

        // Signed: `signed_prefix` is the signed form (boolean TRUE)
        // without the signature field — one byte off from the probe.
        let mut sig_blob = [0u8; ED25519_SIG_BLOB_LEN];
        ed25519_signature_blob(&[0x55; 64], &mut sig_blob).expect("fits");
        let signed_len =
            userauth_publickey_payload(AUTH_USER, &blob, Some(&sig_blob), &mut buf).expect("fits");
        let req = parse_userauth_request(&buf[..signed_len]).expect("signed parses");
        assert!(req.has_signature);
        assert_eq!(req.signed_prefix.len(), probe.len());
        let changed: Vec<usize> = (0..probe.len())
            .filter(|&i| probe[i] != req.signed_prefix[i])
            .collect();
        assert_eq!(changed.len(), 1, "only the boolean differs");
        assert_eq!(req.signed_prefix[changed[0]], 1);
        assert_eq!(probe[changed[0]], 0);
        assert_eq!(parse_ed25519_signature_blob(req.signature), Ok([0x55; 64]));

        // `none`.
        let n = userauth_none_payload(&mut buf).expect("fits");
        let req = parse_userauth_request(&buf[..n]).expect("none parses");
        assert_eq!(req.method, b"none");
        assert!(!req.has_signature);
        assert!(req.key_blob.is_empty());

        // Fail-closed: trailing garbage after `none`, unsupported
        // method, a bad signature blob, a wrong algorithm.
        let mut extra = Vec::from(&buf[..n]);
        extra.push(0);
        assert_eq!(
            parse_userauth_request(&extra),
            Err(UserAuthError::TrailingGarbage)
        );
        let mut p = Vec::new();
        p.push(SSH_MSG_USERAUTH_REQUEST);
        p.extend_from_slice(&4u32.to_be_bytes());
        p.extend_from_slice(b"git!");
        p.extend_from_slice(&14u32.to_be_bytes());
        p.extend_from_slice(AUTH_SERVICE);
        p.extend_from_slice(&8u32.to_be_bytes());
        p.extend_from_slice(b"password");
        assert_eq!(
            parse_userauth_request(&p),
            Err(UserAuthError::UnsupportedMethod)
        );
        let mut bad = Vec::from(&buf[..signed_len]);
        let cut = bad.len() - ED25519_SIG_BLOB_LEN;
        bad[cut + 4 + 11] ^= 0xFF; // corrupt the inner signature length
        assert!(parse_userauth_request(&bad).is_err());
    }

    #[test]
    fn signed_prefix_is_the_signed_request_minus_its_signature() {
        let blob = key_blob_for(0x77);
        let mut probe = [0u8; 256];
        let pn = userauth_publickey_payload(AUTH_USER, &blob, None, &mut probe).expect("fits");
        let mut prefix = [0u8; 256];
        let xn = userauth_signed_prefix(AUTH_USER, &blob, &mut prefix).expect("fits");
        // Same length, and exactly one byte differs: the boolean.
        assert_eq!(pn, xn);
        let different: Vec<usize> = (0..pn).filter(|&i| probe[i] != prefix[i]).collect();
        assert_eq!(different.len(), 1);
        assert_eq!(prefix[different[0]], 1);
        assert_eq!(probe[different[0]], 0);

        // The signed request's own bytes start with that prefix.
        let mut sig = [0u8; ED25519_SIG_BLOB_LEN];
        ed25519_signature_blob(&[9u8; 64], &mut sig).expect("fits");
        let mut signed = [0u8; 512];
        let sn =
            userauth_publickey_payload(AUTH_USER, &blob, Some(&sig), &mut signed).expect("fits");
        assert_eq!(&signed[..xn], &prefix[..xn]);
        assert_eq!(sn, xn + 4 + ED25519_SIG_BLOB_LEN);
    }

    #[test]
    fn base64_decode_is_strict_and_inverts_the_encoder() {
        let mut enc = [0u8; 400];
        let mut dec = [0u8; 300];
        for len in 0..=200usize {
            let input: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let n = base64_encode(&input, true, &mut enc).expect("fits");
            let m = base64_decode(&enc[..n], &mut dec).expect("decodes");
            assert_eq!(&dec[..m], &input[..], "len {len}");
        }
        // Whitespace is trimmed; internal whitespace is not.
        assert_eq!(base64_decode(b"  QUJD\n", &mut dec), Some(3));
        assert_eq!(&dec[..3], b"ABC");
        assert_eq!(base64_decode(b"QU JD", &mut dec), None);
        // Padding rules.
        assert_eq!(base64_decode(b"QQ==", &mut dec), Some(1));
        assert_eq!(base64_decode(b"QUI=", &mut dec), Some(2));
        assert_eq!(base64_decode(b"Q", &mut dec), None);
        assert_eq!(base64_decode(b"QQ=", &mut dec), None);
        assert_eq!(base64_decode(b"Q===", &mut dec), None);
        assert_eq!(base64_decode(b"=QQ=", &mut dec), None);
        assert_eq!(base64_decode(b"QUJD", &mut dec[..2]), None);
    }

    #[test]
    fn authorized_key_line_parses_one_ed25519_entry() {
        let blob = key_blob_for(0x66);
        let mut b64 = [0u8; 200];
        let n = base64_encode(&blob, true, &mut b64).expect("fits");
        let mut line = Vec::from(&b"# a comment\r\nssh-rsa AAAAjunk\r\n"[..]);
        line.extend_from_slice(b"  ssh-ed25519 ");
        line.extend_from_slice(&b64[..n]);
        line.extend_from_slice(b" test@host\r\n");
        let mut out = [0u8; 32];
        assert_eq!(parse_authorized_key(&line, &mut out), Ok(()));
        assert_eq!(out, [0x66; 32]);

        // No ed25519 line at all.
        assert_eq!(
            parse_authorized_key(b"ssh-rsa AAAA\n# nothing\n", &mut out),
            Err(KeyError::Truncated)
        );
        // A malformed ed25519 line must not be skipped silently.
        assert_eq!(
            parse_authorized_key(b"ssh-ed25519 !!!not-base64!!!\n", &mut out),
            Err(KeyError::NotBase64)
        );
        // The blob must be an ed25519 key blob (right algorithm).
        let mut wrong = [0u8; 200];
        let w = base64_encode(&[0u8; ED25519_KEY_BLOB_LEN], true, &mut wrong).expect("fits");
        let mut bad = Vec::from(&b"ssh-ed25519 "[..]);
        bad.extend_from_slice(&wrong[..w]);
        assert_eq!(
            parse_authorized_key(&bad, &mut out),
            Err(KeyError::WrongAlgorithm)
        );
    }

    #[test]
    fn channel_open_and_confirmation_roundtrip() {
        let mut buf = [0u8; 128];
        let n = channel_open_session_payload(3, 65536, 32768, &mut buf).expect("fits");
        let open = parse_channel_open(&buf[..n]).expect("parses");
        assert_eq!(open.channel_type, b"session");
        assert_eq!(
            (open.sender_channel, open.initial_window, open.max_packet),
            (3, 65536, 32768)
        );

        let n = channel_open_confirmation_payload(3, 0, 65536, 32768, &mut buf).expect("fits");
        let conf = parse_channel_open_confirmation(&buf[..n]).expect("parses");
        assert_eq!((conf.recipient_channel, conf.sender_channel), (3, 0));
        assert_eq!((conf.initial_window, conf.max_packet), (65536, 32768));

        // A truncated channel type and trailing garbage are refused.
        assert_eq!(
            parse_channel_open(&[SSH_MSG_CHANNEL_OPEN, 0, 0, 0]),
            Err(ChannelError::Truncated)
        );
        let mut extra = Vec::from(&buf[..n]);
        extra.push(0);
        assert_eq!(
            parse_channel_open_confirmation(&extra),
            Err(ChannelError::TrailingGarbage)
        );
    }

    #[test]
    fn channel_exec_request_data_eof_and_exit_status() {
        let mut buf = [0u8; 256];
        let n =
            channel_request_exec_payload(7, b"echo SSHD_EXEC_OK", true, &mut buf).expect("fits");
        let req = parse_channel_request(&buf[..n]).expect("parses");
        assert_eq!(req.recipient_channel, 7);
        assert_eq!(req.request_type, b"exec");
        assert!(req.want_reply);
        assert_eq!(req.exec_command, b"echo SSHD_EXEC_OK");
        // Empty and over-long commands never reach the wire/parser.
        assert_eq!(channel_request_exec_payload(7, b"", true, &mut buf), None);
        let long = [b'x'; EXEC_COMMAND_MAX + 1];
        assert_eq!(channel_request_exec_payload(7, &long, true, &mut buf), None);

        let n = channel_data_payload(0, b"SSHD_EXEC_OK\n", &mut buf).expect("fits");
        assert_eq!(
            parse_channel_data(&buf[..n]),
            Ok((0, &b"SSHD_EXEC_OK\n"[..]))
        );

        let n = channel_number_payload(SSH_MSG_CHANNEL_EOF, 0, &mut buf).expect("fits");
        assert_eq!(parse_channel_number(&buf[..n], SSH_MSG_CHANNEL_EOF), Ok(0));
        let n = channel_number_payload(SSH_MSG_CHANNEL_CLOSE, 0, &mut buf).expect("fits");
        assert_eq!(
            parse_channel_number(&buf[..n], SSH_MSG_CHANNEL_CLOSE),
            Ok(0)
        );
        // A different message type is refused, not reinterpreted.
        assert_eq!(
            parse_channel_number(&buf[..n], SSH_MSG_CHANNEL_EOF),
            Err(ChannelError::WrongMessage)
        );

        let n = channel_exit_status_payload(0, 0, &mut buf).expect("fits");
        assert_eq!(parse_channel_exit_status(&buf[..n]), Ok((0, 0)));
        let n = channel_exit_status_payload(0, 127, &mut buf).expect("fits");
        assert_eq!(parse_channel_exit_status(&buf[..n]), Ok((0, 127)));
    }

    // ---- adversarial hardening (milestone `ssh-hardening`) --------
    //
    // Gap-filling tests: every public parser must refuse an empty
    // input, every truncation at each field boundary, a declared
    // length that lies (u32::MAX — refused before any byte of the
    // claimed body is waited on), non-printable bytes where text is
    // expected, and buffers one byte short. The categories already
    // covered above (banner bounds and bad bytes, packet padding and
    // block size, hostile EXT_INFO counts, blob lengths and
    // truncations) are not repeated here.

    /// `SSH_MSG_SERVICE_REQUEST` had no host test at all: roundtrip
    /// plus every rejection the server turns into a connection drop.
    #[test]
    fn service_request_roundtrip_and_rejections() {
        let mut p = Vec::new();
        p.push(SSH_MSG_SERVICE_REQUEST);
        p.extend_from_slice(&12u32.to_be_bytes());
        p.extend_from_slice(b"ssh-userauth");
        assert_eq!(parse_service_request(&p), Ok(b"ssh-userauth".as_slice()));
        // Empty input.
        assert_eq!(parse_service_request(&[]), Err(ServiceError::Truncated));
        // Wrong message byte.
        let mut wrong = p.clone();
        wrong[0] = SSH_MSG_SERVICE_ACCEPT;
        assert_eq!(
            parse_service_request(&wrong),
            Err(ServiceError::WrongMessage)
        );
        // Every truncation, at each field boundary.
        for cut in 0..p.len() {
            assert!(parse_service_request(&p[..cut]).is_err(), "cut {cut}");
        }
        // A declared length that lies (u32::MAX): refused by the
        // bounds check, never waited on.
        let mut liar = Vec::new();
        liar.push(SSH_MSG_SERVICE_REQUEST);
        liar.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_service_request(&liar), Err(ServiceError::Truncated));
        // ...and one that fits its own header but overruns the payload.
        let mut short = p.clone();
        short[1..5].copy_from_slice(&13u32.to_be_bytes());
        assert_eq!(parse_service_request(&short), Err(ServiceError::Truncated));
        // Nothing may follow the name.
        let mut tail = p.clone();
        tail.push(0);
        assert_eq!(
            parse_service_request(&tail),
            Err(ServiceError::TrailingGarbage)
        );
        // Non-printable "service" bytes are surfaced as an opaque
        // field — the *caller* must compare against the exact ASCII
        // name (the sshd does: `name != b"ssh-userauth"` → drop).
        let mut junk = Vec::new();
        junk.push(SSH_MSG_SERVICE_REQUEST);
        junk.extend_from_slice(&3u32.to_be_bytes());
        junk.extend_from_slice(b"\x01\x02\x03");
        assert_eq!(parse_service_request(&junk), Ok(b"\x01\x02\x03".as_slice()));
    }

    /// `SSH_MSG_KEXDH_INIT` had only spot checks: every truncation,
    /// the empty payload, a lying u32::MAX length and trailing bytes.
    #[test]
    fn kexdh_init_refuses_truncation_giant_lengths_and_trailing_bytes() {
        let mut init = [0u8; 64];
        let n = kexdh_init_payload(&[7u8; 32], &mut init).expect("fits");
        assert_eq!(parse_kexdh_init(&init[..n]), Ok([7u8; 32]));
        for cut in 0..n {
            assert!(parse_kexdh_init(&init[..cut]).is_err(), "cut {cut}");
        }
        assert_eq!(parse_kexdh_init(&[]), Err(KexDhError::Truncated));
        // Declared length u32::MAX: the `== 32` check refuses it
        // before any body byte is waited on.
        let mut liar = vec![SSH_MSG_KEXDH_INIT];
        liar.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_kexdh_init(&liar), Err(KexDhError::BadPublicKey));
        // Bytes after the 32-byte value.
        let mut tail = init[..n].to_vec();
        tail.push(0);
        assert_eq!(parse_kexdh_init(&tail), Err(KexDhError::TrailingGarbage));
    }

    /// The three *outer* string lengths of `SSH_MSG_KEXDH_REPLY`
    /// (K_S, f, signature) lying as u32::MAX: each is refused from
    /// the length field alone.
    #[test]
    fn kexdh_reply_refuses_giant_declared_lengths() {
        let full = valid_kexdh_reply();
        // Layout: msg(1) + string(4+51 K_S) + string(4+32 f) +
        // string(4+83 signature) — f's length sits at 56, the
        // signature's at 92.
        assert_eq!(full.len(), 1 + 4 + 51 + 4 + 32 + 4 + 83);
        let mut p = full.clone();
        p[1..5].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::Truncated));
        let mut p = full.clone();
        p[56..60].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::BadPublicKey));
        let mut p = full;
        p[92..96].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_kexdh_reply(&p), Err(KexDhError::Truncated));
    }

    /// Declared u32::MAX lengths in the auth answers: refused by the
    /// bounds check (Truncated), never waited on — each payload here
    /// is nothing but its header plus the lying length.
    #[test]
    fn auth_answers_refuse_giant_declared_lengths() {
        // USERAUTH_FAILURE: methods name-list length = u32::MAX.
        let mut f = Vec::new();
        f.push(SSH_MSG_USERAUTH_FAILURE);
        f.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_userauth_failure(&f), Err(UserAuthError::Truncated));
        // USERAUTH_PK_OK: algorithm length = u32::MAX, then (with a
        // well-formed algorithm) the key-blob length = u32::MAX.
        let mut pk = Vec::new();
        pk.push(SSH_MSG_USERAUTH_PK_OK);
        pk.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_userauth_pk_ok(&pk), Err(UserAuthError::Truncated));
        let mut pk = Vec::new();
        pk.push(SSH_MSG_USERAUTH_PK_OK);
        pk.extend_from_slice(&11u32.to_be_bytes());
        pk.extend_from_slice(b"ssh-ed25519");
        pk.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_userauth_pk_ok(&pk), Err(UserAuthError::Truncated));
        // SERVICE_ACCEPT: service-name length = u32::MAX.
        let mut sa = Vec::new();
        sa.push(SSH_MSG_SERVICE_ACCEPT);
        sa.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_service_accept(&sa), Err(ServiceError::Truncated));
        // (USERAUTH_BANNER already has its own u32::MAX message-length
        // test above.)
    }

    /// `SSH_MSG_USERAUTH_REQUEST` is the server's auth gate: every
    /// truncation of the probe, the signed request and the `none`
    /// payload must be refused, plus empty input, a lying u32::MAX
    /// user length, an empty user name, a non-boolean flag and a
    /// wrong message byte.
    #[test]
    fn userauth_request_refuses_truncation_and_giant_lengths() {
        let blob = key_blob_for(0x55);
        let mut sig_blob = [0u8; ED25519_SIG_BLOB_LEN];
        ed25519_signature_blob(&[0x77; 64], &mut sig_blob).expect("fits");
        let mut buf = [0u8; 512];
        for signed in [false, true] {
            let n = userauth_publickey_payload(
                AUTH_USER,
                &blob,
                signed.then_some(&sig_blob[..]),
                &mut buf,
            )
            .expect("fits");
            for cut in 0..n {
                assert!(
                    parse_userauth_request(&buf[..cut]).is_err(),
                    "signed {signed}: cut {cut} parsed"
                );
            }
            assert!(parse_userauth_request(&buf[..n]).is_ok());
        }
        let n = userauth_none_payload(&mut buf).expect("fits");
        for cut in 0..n {
            assert!(
                parse_userauth_request(&buf[..cut]).is_err(),
                "none: cut {cut} parsed"
            );
        }
        assert_eq!(parse_userauth_request(&[]), Err(UserAuthError::Truncated));
        // The user length lies as u32::MAX: refused before its bytes.
        let mut liar = Vec::new();
        liar.push(SSH_MSG_USERAUTH_REQUEST);
        liar.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_userauth_request(&liar), Err(UserAuthError::Truncated));
        // An empty user name is refused (RFC4254 §5.1).
        let mut empty_user = Vec::new();
        empty_user.push(SSH_MSG_USERAUTH_REQUEST);
        empty_user.extend_from_slice(&0u32.to_be_bytes());
        empty_user.extend_from_slice(&14u32.to_be_bytes());
        empty_user.extend_from_slice(AUTH_SERVICE);
        empty_user.extend_from_slice(&4u32.to_be_bytes());
        empty_user.extend_from_slice(b"none");
        assert_eq!(
            parse_userauth_request(&empty_user),
            Err(UserAuthError::Truncated)
        );
        // The publickey flag is an RFC4251 boolean.
        let n = userauth_publickey_payload(AUTH_USER, &blob, None, &mut buf).expect("fits");
        let mut bad = buf[..n].to_vec();
        bad[1 + 7 + 18 + 13] = 2;
        assert_eq!(parse_userauth_request(&bad), Err(UserAuthError::BadBoolean));
        // Wrong message byte.
        let mut wrong = buf[..n].to_vec();
        wrong[0] = SSH_MSG_USERAUTH_FAILURE;
        assert_eq!(
            parse_userauth_request(&wrong),
            Err(UserAuthError::WrongMessage)
        );
    }

    /// `CHANNEL_OPEN`/`CHANNEL_OPEN_CONFIRMATION`: every truncation,
    /// empty input, a lying u32::MAX type length, a wrong message
    /// byte — and the open parser is a field reader: it *surfaces*
    /// any channel type for the caller to refuse (the sshd drops on
    /// anything but `"session"` instead of replying
    /// `CHANNEL_OPEN_FAILURE` — see docs/ssh-audit.md).
    #[test]
    fn channel_open_refuses_truncation_and_giant_lengths() {
        let mut buf = [0u8; 128];
        let n = channel_open_session_payload(3, 65536, 32768, &mut buf).expect("fits");
        assert_eq!(n, 24);
        for cut in 0..n {
            assert!(parse_channel_open(&buf[..cut]).is_err(), "cut {cut}");
        }
        assert_eq!(parse_channel_open(&[]), Err(ChannelError::Truncated));
        let mut liar = Vec::new();
        liar.push(SSH_MSG_CHANNEL_OPEN);
        liar.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_channel_open(&liar), Err(ChannelError::Truncated));
        // A different message byte is refused.
        let mut wrong = buf[..n].to_vec();
        wrong[0] = SSH_MSG_CHANNEL_REQUEST;
        assert_eq!(parse_channel_open(&wrong), Err(ChannelError::WrongMessage));
        // The raw channel type is surfaced, never silently accepted:
        // the caller compares it (sshd: `!= b"session"` → drop).
        let mut foreign = Vec::new();
        foreign.push(SSH_MSG_CHANNEL_OPEN);
        foreign.extend_from_slice(&(b"direct-tcpip".len() as u32).to_be_bytes());
        foreign.extend_from_slice(b"direct-tcpip");
        foreign.extend_from_slice(&9u32.to_be_bytes());
        foreign.extend_from_slice(&65536u32.to_be_bytes());
        foreign.extend_from_slice(&32768u32.to_be_bytes());
        let open = parse_channel_open(&foreign).expect("field reader");
        assert_eq!(open.channel_type, b"direct-tcpip");
        assert_eq!(open.sender_channel, 9);

        // Confirmation: same treatment.
        let n = channel_open_confirmation_payload(3, 0, 65536, 32768, &mut buf).expect("fits");
        assert_eq!(n, 17);
        for cut in 0..n {
            assert!(
                parse_channel_open_confirmation(&buf[..cut]).is_err(),
                "cut {cut}"
            );
        }
        assert_eq!(
            parse_channel_open_confirmation(&[]),
            Err(ChannelError::Truncated)
        );
        let mut wrong = buf[..n].to_vec();
        wrong[0] = SSH_MSG_CHANNEL_OPEN;
        assert_eq!(
            parse_channel_open_confirmation(&wrong),
            Err(ChannelError::WrongMessage)
        );
    }

    /// `CHANNEL_REQUEST`: the `exec` bounds are checked *before* the
    /// command bytes are waited on (u32::MAX and `EXEC_COMMAND_MAX+1`
    /// both → `BadCommand`), plus truncation at every boundary, empty
    /// input, a lying type length, a bad boolean, and the two
    /// non-exec shapes (a bare one parses; one *with* arguments is
    /// `TrailingGarbage` — ssh-wire has no non-exec payload grammar,
    /// which the sshd turns into a drop: docs/ssh-audit.md).
    #[test]
    fn channel_request_enforces_bounds_before_waiting() {
        fn chan_req(request_type: &[u8], want_reply: u8, command: Option<&[u8]>) -> Vec<u8> {
            let mut v = Vec::new();
            v.push(SSH_MSG_CHANNEL_REQUEST);
            v.extend_from_slice(&7u32.to_be_bytes()); // recipient channel
            v.extend_from_slice(&(request_type.len() as u32).to_be_bytes());
            v.extend_from_slice(request_type);
            v.push(want_reply);
            if let Some(c) = command {
                v.extend_from_slice(&(c.len() as u32).to_be_bytes());
                v.extend_from_slice(c);
            }
            v
        }

        let full = chan_req(b"exec", 1, Some(b"echo hi"));
        let req = parse_channel_request(&full).expect("parses");
        assert_eq!(req.exec_command, b"echo hi");
        for cut in 0..full.len() {
            assert!(
                parse_channel_request(&full[..cut]).is_err(),
                "cut {cut} parsed"
            );
        }
        assert_eq!(parse_channel_request(&[]), Err(ChannelError::Truncated));

        // Wrong message byte.
        let mut wrong = full.clone();
        wrong[0] = SSH_MSG_CHANNEL_DATA;
        assert_eq!(
            parse_channel_request(&wrong),
            Err(ChannelError::WrongMessage)
        );

        // The request-type length lies as u32::MAX.
        let mut liar = full.clone();
        liar[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_channel_request(&liar), Err(ChannelError::Truncated));

        // `want_reply` is an RFC4251 boolean.
        let bad = chan_req(b"exec", 2, Some(b"x"));
        assert_eq!(parse_channel_request(&bad), Err(ChannelError::BadBoolean));

        // exec command bounds: empty, one over the cap and u32::MAX
        // are all refused from the length field alone.
        assert_eq!(
            parse_channel_request(&chan_req(b"exec", 1, Some(b""))),
            Err(ChannelError::BadCommand)
        );
        assert_eq!(
            parse_channel_request(&chan_req(b"exec", 1, Some(&[b'x'; EXEC_COMMAND_MAX + 1]))),
            Err(ChannelError::BadCommand)
        );
        let mut giant = chan_req(b"exec", 1, Some(b"x"));
        let clen_at = giant.len() - 4 - 1; // command byte precedes its length
        giant[clen_at..clen_at + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_channel_request(&giant), Err(ChannelError::BadCommand));

        // Exactly at the cap: accepted.
        let at_cap = chan_req(b"exec", 1, Some(&[b'x'; EXEC_COMMAND_MAX]));
        let req = parse_channel_request(&at_cap).expect("at the cap");
        assert_eq!(req.exec_command.len(), EXEC_COMMAND_MAX);

        // A non-exec request with *no* arguments parses with an empty
        // command (the caller replies CHANNEL_FAILURE).
        let bare = chan_req(b"break", 1, None);
        let req = parse_channel_request(&bare).expect("bare break");
        assert_eq!(req.request_type, b"break");
        assert!(req.exec_command.is_empty());
        // ...with arguments it is TrailingGarbage → sshd drops the
        // connection instead of CHANNEL_FAILURE (docs/ssh-audit.md).
        let with_args = chan_req(b"pty-req", 1, Some(b"term"));
        assert_eq!(
            parse_channel_request(&with_args),
            Err(ChannelError::TrailingGarbage)
        );
    }

    /// The single-field channel messages (`CHANNEL_SUCCESS`/
    /// `FAILURE`/`EOF`/`CLOSE`, `CHANNEL_DATA`, `exit-status`):
    /// empty input, every truncation, a wrong message byte, lying
    /// u32::MAX lengths, a bad boolean and trailing bytes.
    #[test]
    fn channel_small_messages_refuse_truncation_and_trailing_bytes() {
        let mut buf = [0u8; 64];

        // One-channel messages.
        let n = channel_number_payload(SSH_MSG_CHANNEL_EOF, 9, &mut buf).expect("fits");
        assert_eq!(n, 5);
        for cut in 0..n {
            assert!(
                parse_channel_number(&buf[..cut], SSH_MSG_CHANNEL_EOF).is_err(),
                "cut {cut}"
            );
        }
        assert_eq!(
            parse_channel_number(&[], SSH_MSG_CHANNEL_EOF),
            Err(ChannelError::Truncated)
        );
        let mut tail = buf[..n].to_vec();
        tail.push(0);
        assert_eq!(
            parse_channel_number(&tail, SSH_MSG_CHANNEL_EOF),
            Err(ChannelError::TrailingGarbage)
        );
        assert_eq!(
            parse_channel_number(&[SSH_MSG_CHANNEL_DATA, 0, 0, 0, 0], SSH_MSG_CHANNEL_EOF),
            Err(ChannelError::WrongMessage)
        );

        // CHANNEL_DATA.
        let n = channel_data_payload(3, b"hello", &mut buf).expect("fits");
        assert_eq!(n, 14);
        for cut in 0..n {
            assert!(parse_channel_data(&buf[..cut]).is_err(), "cut {cut}");
        }
        assert_eq!(parse_channel_data(&[]), Err(ChannelError::Truncated));
        let mut wrong = buf[..n].to_vec();
        wrong[0] = SSH_MSG_CHANNEL_EXTENDED_DATA;
        assert_eq!(parse_channel_data(&wrong), Err(ChannelError::WrongMessage));
        // Declared data length u32::MAX: refused before its bytes.
        let mut liar = buf[..n].to_vec();
        liar[5..9].copy_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(parse_channel_data(&liar), Err(ChannelError::Truncated));
        let mut tail = buf[..n].to_vec();
        tail.push(0);
        assert_eq!(
            parse_channel_data(&tail),
            Err(ChannelError::TrailingGarbage)
        );

        // exit-status.
        let n = channel_exit_status_payload(3, 7, &mut buf).expect("fits");
        assert_eq!(n, 25);
        for cut in 0..n {
            assert!(parse_channel_exit_status(&buf[..cut]).is_err(), "cut {cut}");
        }
        assert_eq!(parse_channel_exit_status(&[]), Err(ChannelError::Truncated));
        let mut wrong = buf[..n].to_vec();
        wrong[0] = SSH_MSG_CHANNEL_REQUEST + 1;
        assert_eq!(
            parse_channel_exit_status(&wrong),
            Err(ChannelError::WrongMessage)
        );
        // The request-type length must be exactly 11 ("exit-status").
        let mut short_name = buf[..n].to_vec();
        short_name[5..9].copy_from_slice(&10u32.to_be_bytes());
        assert_eq!(
            parse_channel_exit_status(&short_name),
            Err(ChannelError::WrongMessage)
        );
        // `want_reply` is a boolean.
        let mut bad_bool = buf[..n].to_vec();
        bad_bool[20] = 2;
        assert_eq!(
            parse_channel_exit_status(&bad_bool),
            Err(ChannelError::BadBoolean)
        );
        let mut tail = buf[..n].to_vec();
        tail.push(0);
        assert_eq!(
            parse_channel_exit_status(&tail),
            Err(ChannelError::TrailingGarbage)
        );
    }

    /// Every S5 encoder succeeds at its exact size and refuses one
    /// byte short — never a panic, never a partial frame.
    #[test]
    fn s5_encoders_refuse_a_one_byte_short_buffer() {
        macro_rules! exact {
            ($name:literal, $enc:expr) => {{
                let mut buf = [0u8; 512];
                let n = ($enc)(&mut buf[..]).expect(concat!($name, " fits"));
                assert_eq!(
                    ($enc)(&mut buf[..n]),
                    Some(n),
                    "{name} at its exact size",
                    name = $name
                );
                assert_eq!(
                    ($enc)(&mut buf[..n - 1]),
                    None,
                    "{name} one byte short",
                    name = $name
                );
            }};
        }
        let blob = key_blob_for(0x21);
        let mut sig_blob = [0u8; ED25519_SIG_BLOB_LEN];
        ed25519_signature_blob(&[0x33; 64], &mut sig_blob).expect("fits");
        exact!("channel_open_session", |out: &mut [u8]| {
            channel_open_session_payload(3, 65536, 32768, out)
        });
        exact!("channel_open_confirmation", |out: &mut [u8]| {
            channel_open_confirmation_payload(3, 0, 65536, 32768, out)
        });
        exact!("channel_request_exec", |out: &mut [u8]| {
            channel_request_exec_payload(7, b"echo hi", true, out)
        });
        exact!("channel_number", |out: &mut [u8]| {
            channel_number_payload(SSH_MSG_CHANNEL_EOF, 0, out)
        });
        exact!("channel_data", |out: &mut [u8]| {
            channel_data_payload(0, b"hello", out)
        });
        exact!("channel_exit_status", |out: &mut [u8]| {
            channel_exit_status_payload(0, 7, out)
        });
        exact!("service_accept", |out: &mut [u8]| {
            service_accept_payload(b"ssh-userauth", out)
        });
        exact!("userauth_failure", |out: &mut [u8]| {
            userauth_failure_payload(b"publickey", false, out)
        });
        exact!("userauth_success", |out: &mut [u8]| {
            userauth_success_payload(out)
        });
        exact!("userauth_pk_ok", |out: &mut [u8]| {
            userauth_pk_ok_payload(&blob, out)
        });
        exact!("userauth_banner", |out: &mut [u8]| {
            userauth_banner_payload(b"hi", out)
        });
        exact!("kexdh_reply", |out: &mut [u8]| {
            crate::kexdh_reply_payload(&blob, &[9u8; 32], &sig_blob, out)
        });
    }

    /// `parse_authorized_key` on hostile *file* input: empty file,
    /// comment/blank-only file, a line with no key body, an oversized
    /// base64 body (the fixed 96-byte scratch buffer must fail it,
    /// never truncate it into a shorter "key"), and a valid line with
    /// no trailing newline.
    #[test]
    fn authorized_key_refuses_empty_and_oversized_input() {
        let mut out = [0u8; 32];
        // Empty input.
        assert_eq!(
            parse_authorized_key(b"", &mut out),
            Err(KeyError::Truncated)
        );
        // Nothing but comments and blank lines.
        assert_eq!(
            parse_authorized_key(b"# comment\r\n\r\n \t\n", &mut out),
            Err(KeyError::Truncated)
        );
        // `ssh-ed25519` with no space and no body.
        assert_eq!(
            parse_authorized_key(b"ssh-ed25519\n", &mut out),
            Err(KeyError::WrongAlgorithm)
        );
        // A trailing space is eaten by the line trimmer, so this
        // degenerates to the no-space case above: WrongAlgorithm.
        assert_eq!(
            parse_authorized_key(b"ssh-ed25519 \n", &mut out),
            Err(KeyError::WrongAlgorithm)
        );
        // ...and a body that is *only* whitespace the line trimmer
        // does not eat (it only trims ' ' and '\t'; `trim_ascii_start`
        // then eats a form feed) is the empty-body refusal.
        assert_eq!(
            parse_authorized_key(b"ssh-ed25519 \x0c\n", &mut out),
            Err(KeyError::Truncated)
        );
        // A base64 body that would decode past the fixed 96-byte
        // scratch buffer: refused as malformed, never truncated into
        // a shorter key.
        let mut line = Vec::from(b"ssh-ed25519 ");
        line.extend(std::iter::repeat_n(b'A', 300));
        assert_eq!(
            parse_authorized_key(&line, &mut out),
            Err(KeyError::NotBase64)
        );
        // A valid line parses with *no* trailing newline at all.
        let blob = key_blob_for(0x66);
        let mut b64 = [0u8; 200];
        let n = base64_encode(&blob, true, &mut b64).expect("fits");
        let mut line = Vec::from(b"ssh-ed25519 ");
        line.extend_from_slice(&b64[..n]);
        assert_eq!(parse_authorized_key(&line, &mut out), Ok(()));
        assert_eq!(out, [0x66; 32]);
        // The comment tail is opaque: non-printable bytes there are
        // ignored (never parsed, never logged).
        let mut commented = line.clone();
        commented.extend_from_slice(b" \x01\x02\x7f note");
        assert_eq!(parse_authorized_key(&commented, &mut out), Ok(()));
        assert_eq!(out, [0x66; 32]);
    }

    /// Empty hex seed input (the whitespace-only case is covered
    /// above; this is the raw empty slice).
    #[test]
    fn seed_hex_refuses_empty_input() {
        let mut seed = [0u8; 32];
        assert_eq!(parse_seed_hex(b"", &mut seed), Err(KeyError::BadHexLength));
        assert_eq!(
            parse_seed_hex(b"00", &mut seed),
            Err(KeyError::BadHexLength)
        );
    }

    /// RFC4648 §3.5: a decoder *MAY* reject non-canonical trailing
    /// bits; ours accepts them — the decoded key bytes are what every
    /// comparison uses, so there is no ambiguity to exploit. Pinned
    /// so a future strictness change is a deliberate one.
    #[test]
    fn base64_decode_pins_non_canonical_trailing_bits_as_accepted() {
        let mut canonical = [0u8; 4];
        let mut non_canonical = [0u8; 4];
        let a = base64_decode(b"Zg==", &mut canonical).expect("canonical");
        let b = base64_decode(b"Zh==", &mut non_canonical).expect("non-canonical");
        assert_eq!(&canonical[..a], &non_canonical[..b]);
        assert_eq!(&canonical[..a], b"f");
    }
}
