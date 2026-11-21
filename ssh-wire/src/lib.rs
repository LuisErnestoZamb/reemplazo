//! SSH wire codec — milestone S1 of docs/git-ssh-deps.md §B.4: the
//! RFC4253 identification banner (§4.2), the unencrypted binary
//! packet framing (§6), `SSH_MSG_KEXINIT` parse/encode (§7.1) and the
//! algorithm intersection. **Plaintext only** — key exchange and
//! crypto arrive with S2; nothing in this crate implements (or may
//! ever implement) a cryptographic primitive.
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
    if !(packet_length + 4).is_multiple_of(BLOCK_SIZE) {
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
/// `github.com:22` today).
pub const KEX_ALGORITHMS: &str = "curve25519-sha256";
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
    // Payload: type + cookie + ten (len, list) pairs + bool + reserved.
    let payload_length = 1 + 16 + 10 * 4 + OUR_LISTS.iter().map(|l| l.len()).sum::<usize>() + 1 + 4;
    // Bytes on the wire before padding: length field + padding_length
    // byte + payload.
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
    for list in OUR_LISTS {
        dst[w..w + 4].copy_from_slice(&u32::try_from(list.len()).ok()?.to_be_bytes());
        w += 4;
        dst[w..w + list.len()].copy_from_slice(list.as_bytes());
        w += list.len();
    }
    dst[w] = 0; // first_kex_packet_follows = false
    w += 1;
    dst[w..w + 4].copy_from_slice(&0u32.to_be_bytes()); // reserved = 0
    // Zero the padding explicitly: `out` may hold caller garbage.
    for byte in dst[w..].iter_mut() {
        *byte = 0;
    }
    Some(total)
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
    if n.kex != Some(KEX_ALGORITHMS) {
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

#[cfg(test)]
mod tests {
    use super::*;
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
        // server wins.
        assert_eq!(n.kex, Some(KEX_ALGORITHMS));
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
}
