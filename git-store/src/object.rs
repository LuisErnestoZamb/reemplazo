//! Loose-object encoding and decoding — git's
//! [object format](https://git-scm.com/docs/gitformat-objects):
//!
//! ```text
//! preimage  = "<type> SP <decimal-size> NUL <content>"
//! oid       = SHA-1(preimage)                  (20 raw bytes, 40 hex)
//! on disk   = zlib-deflate(preimage) at
//!             .git/objects/<first 2 hex>/<remaining 38 hex>
//! ```
//!
//! Decompression/compression is `miniz_oxide` (reviewed in G3a); the
//! hash is `sha1` (same review). Both are no_std and allocation-bounded
//! **by this module**: the inflate call is given an explicit output cap
//! (`content cap + header cap`), and the compressed input is capped
//! before it is handed to the inflater, so a hostile file cannot grow
//! the kernel heap without limit.
//!
//! Compression level: `1` (`Z_BEST_SPEED`), which is exactly git's
//! default for *loose* objects (`core.looseCompression`, whose default
//! is 1; the pack writer uses `core.compression`). Speed matters on the
//! 5400 rpm target and the deflate ratio difference is noise next to
//! PIO write latency.

use crate::Error;
use alloc::vec::Vec;
use miniz_oxide::deflate::compress_to_vec_zlib;
use miniz_oxide::inflate::{TINFLStatus, decompress_to_vec_zlib_with_limit};
use sha1::{Digest, Sha1};

/// Largest object content this crate will encode or decode (8 MiB).
/// The kernel's fetch already caps a single object at 4 MiB, so this is
/// a crate-level ceiling, not the runtime one.
pub const MAX_OBJECT_SIZE: usize = 8 * 1024 * 1024;
/// Largest compressed loose object accepted, including zlib's worst-case
/// overhead over `MAX_OBJECT_SIZE` (deflate's stored-block overhead is
/// ~5 bytes per 64 KiB plus the 6-byte zlib wrapper; 64 KiB of slack is
/// generous).
pub const MAX_COMPRESSED_SIZE: usize = MAX_OBJECT_SIZE + 64 * 1024;
/// Longest header `<type> SP <20 digits> NUL` we will consider. The type
/// is at most `commit` (6) + space + 20 digits + NUL.
const MAX_HEADER: usize = 28;
/// Loose object relative path length: `objects/xx/` (11) + 38 hex.
pub const LOOSE_PATH_LEN: usize = 7 + 1 + 2 + 1 + 38;
/// The zlib level git uses for loose objects (`core.looseCompression`
/// default = 1).
const LOOSE_ZLIB_LEVEL: u8 = 1;

const HEX: &[u8; 16] = b"0123456789abcdef";

/// The four git object types. Deltas are pack representations, never
/// object types, so they are absent here (same four as
/// `git_pack::Kind`; the crates cannot depend on each other).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// `commit`
    Commit,
    /// `tree`
    Tree,
    /// `blob`
    Blob,
    /// `tag`
    Tag,
}

impl Kind {
    /// The type name as git spells it in the object-id preimage.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        }
    }

    /// Parse the type name from a loose/commit header.
    pub fn from_name(name: &[u8]) -> Option<Kind> {
        match name {
            b"commit" => Some(Kind::Commit),
            b"tree" => Some(Kind::Tree),
            b"blob" => Some(Kind::Blob),
            b"tag" => Some(Kind::Tag),
            _ => None,
        }
    }
}

/// A decoded loose object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The declared type.
    pub kind: Kind,
    /// SHA-1 of the preimage — equals the object's path-derived id.
    pub oid: [u8; 20],
    /// The decompressed content (header stripped).
    pub data: Vec<u8>,
}

/// An encoded loose object, ready to be written at [`loose_path`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseObject {
    /// The object id (also the path's hex).
    pub oid: [u8; 20],
    /// zlib-deflate of the preimage — the bytes that go on disk.
    pub compressed: Vec<u8>,
}

/// SHA-1 over `"<type> <len>\0<data>"` — git's object id.
///
/// Same algorithm as `git_pack::object_id` (duplicated because the
/// store crate must not depend on the pack decoder; both are asserted
/// against the canonical empty-object constants in the tests).
pub fn object_oid(kind: Kind, data: &[u8]) -> [u8; 20] {
    let (digits, start) = decimal(data.len());
    let mut hasher = Sha1::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b" ");
    for &digit in digits.iter().skip(start) {
        hasher.update([digit]);
    }
    hasher.update(b"\0");
    hasher.update(data);
    finish(hasher)
}

/// Format a 20-byte id as 40 lowercase hex characters.
pub fn hex_oid(oid: &[u8; 20]) -> [u8; 40] {
    let mut out = [0u8; 40];
    for (pair, &byte) in out.as_chunks_mut::<2>().0.iter_mut().zip(oid) {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 0x0F)];
    }
    out
}

/// Parse exactly 40 lowercase hex characters. Uppercase is refused:
/// git writes lowercase and a ref/oid file with uppercase is not what
/// git produced (fail-closed beats leniency on the read side).
pub fn parse_oid(hex: &[u8]) -> Result<[u8; 20], Error> {
    if hex.len() != 40 {
        return Err(Error::BadOid);
    }
    let mut oid = [0u8; 20];
    for (slot, pair) in oid.iter_mut().zip(hex.as_chunks::<2>().0) {
        let hi = hex_digit(pair[0]).ok_or(Error::BadOid)?;
        let lo = hex_digit(pair[1]).ok_or(Error::BadOid)?;
        *slot = (hi << 4) | lo;
    }
    Ok(oid)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// The `.git/`-relative path a loose object lives at:
/// `objects/ab/cdef…` (2 hex directory + 38 hex file).
pub fn loose_path(oid: &[u8; 20]) -> [u8; LOOSE_PATH_LEN] {
    let hex = hex_oid(oid);
    let mut out = [0u8; LOOSE_PATH_LEN];
    out[..7].copy_from_slice(b"objects");
    out[7] = b'/';
    out[8..10].copy_from_slice(&hex[..2]);
    out[10] = b'/';
    out[11..].copy_from_slice(&hex[2..]);
    out
}

/// Build the preimage `<type> SP <size> NUL <data>`, refusing content
/// over [`MAX_OBJECT_SIZE`].
pub fn encode_preimage(kind: Kind, data: &[u8]) -> Result<Vec<u8>, Error> {
    encode_preimage_with_limit(kind, data, MAX_OBJECT_SIZE)
}

/// [`encode_preimage`] with a caller-tightened content cap.
pub fn encode_preimage_with_limit(
    kind: Kind,
    data: &[u8],
    max_size: usize,
) -> Result<Vec<u8>, Error> {
    if data.len() > max_size || data.len() > MAX_OBJECT_SIZE {
        return Err(Error::ObjectTooLarge);
    }
    let name = kind.as_str().as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(name);
    out.push(b' ');
    push_decimal(&mut out, data.len());
    out.push(0);
    out.extend_from_slice(data);
    Ok(out)
}

/// Encode a loose object: preimage → oid → zlib.
pub fn encode_loose(kind: Kind, data: &[u8]) -> Result<LooseObject, Error> {
    encode_loose_with_limit(kind, data, MAX_OBJECT_SIZE)
}

/// [`encode_loose`] with a caller-tightened content cap. Peak heap is
/// `2 × (header + data)` while the deflate output is built; the
/// preimage is dropped before this returns.
pub fn encode_loose_with_limit(
    kind: Kind,
    data: &[u8],
    max_size: usize,
) -> Result<LooseObject, Error> {
    let preimage = encode_preimage_with_limit(kind, data, max_size)?;
    let mut hasher = Sha1::new();
    hasher.update(&preimage);
    let oid = finish(hasher);
    let compressed = compress_to_vec_zlib(&preimage, LOOSE_ZLIB_LEVEL);
    if compressed.len() > MAX_COMPRESSED_SIZE {
        return Err(Error::CompressedTooLarge);
    }
    Ok(LooseObject { oid, compressed })
}

/// Inflate + parse a loose object, capped at [`MAX_OBJECT_SIZE`].
pub fn decode_loose(compressed: &[u8]) -> Result<Object, Error> {
    decode_loose_with_limit(compressed, MAX_OBJECT_SIZE)
}

/// [`decode_loose`] with a caller-tightened content cap. The inflate
/// bound is `max_size + MAX_HEADER`; the header's declared size is then
/// checked against the actual remaining bytes, so a stream that expands
/// to more than it declares still fails.
pub fn decode_loose_with_limit(compressed: &[u8], max_size: usize) -> Result<Object, Error> {
    if compressed.is_empty() || compressed.len() > MAX_COMPRESSED_SIZE {
        return Err(Error::InputTooLarge);
    }
    let content_cap = core::cmp::min(max_size, MAX_OBJECT_SIZE);
    let inflate_cap = content_cap
        .checked_add(MAX_HEADER)
        .ok_or(Error::ObjectTooLarge)?;
    let preimage = decompress_to_vec_zlib_with_limit(compressed, inflate_cap).map_err(|e| {
        if e.status == TINFLStatus::HasMoreOutput {
            Error::ObjectTooLarge
        } else {
            Error::CorruptZlib
        }
    })?;
    parse_preimage(preimage, content_cap)
}

fn parse_preimage(mut preimage: Vec<u8>, max_size: usize) -> Result<Object, Error> {
    let space = preimage
        .iter()
        .position(|&b| b == b' ')
        .ok_or(Error::BadHeader)?;
    let type_bytes = preimage.get(..space).ok_or(Error::BadHeader)?;
    if type_bytes.is_empty() || type_bytes.len() > 6 {
        return Err(Error::BadHeader);
    }
    let kind = Kind::from_name(type_bytes).ok_or(Error::UnknownType)?;

    let rest = preimage.get(space + 1..).ok_or(Error::BadHeader)?;
    let nul = rest.iter().position(|&b| b == 0).ok_or(Error::BadHeader)?;
    if nul == 0 || nul > 20 {
        return Err(Error::BadHeader);
    }
    let digits = rest.get(..nul).ok_or(Error::BadHeader)?;
    if digits.len() > 1 && digits.first() == Some(&b'0') {
        return Err(Error::BadHeader); // non-canonical leading zero
    }
    let mut size = 0usize;
    for &byte in digits {
        if !byte.is_ascii_digit() {
            return Err(Error::BadHeader);
        }
        size = size
            .checked_mul(10)
            .and_then(|v| v.checked_add(usize::from(byte - b'0')))
            .ok_or(Error::ObjectTooLarge)?;
    }
    if size > max_size {
        return Err(Error::ObjectTooLarge);
    }
    let header_len = space
        .checked_add(1)
        .and_then(|v| v.checked_add(nul))
        .and_then(|v| v.checked_add(1))
        .ok_or(Error::BadHeader)?;
    if preimage.len() < header_len {
        return Err(Error::BadHeader);
    }
    if preimage.len() - header_len != size {
        return Err(Error::SizeMismatch);
    }

    let mut hasher = Sha1::new();
    hasher.update(&preimage);
    let oid = finish(hasher);

    preimage.drain(..header_len);
    Ok(Object {
        kind,
        oid,
        data: preimage,
    })
}

fn push_decimal(out: &mut Vec<u8>, n: usize) {
    let (digits, start) = decimal(n);
    out.extend(digits.iter().skip(start));
}

/// Decimal digits of `n` right-aligned in a 20-byte buffer (`usize` is
/// at most 20 decimal digits); `start` is the first significant byte.
fn decimal(mut n: usize) -> ([u8; 20], usize) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        // `i` counts down from 20 and a usize never needs more than 20
        // digits, so the slot exists; `get_mut` keeps that panic-free.
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    (buf, i)
}

fn finish(hasher: Sha1) -> [u8; 20] {
    let digest = hasher.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(digest.as_slice());
    oid
}
