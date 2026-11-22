//! git **packfile v2** decoding: the pure-protocol half of `git fetch`
//! (milestone G3a of `docs/git-ssh-deps.md` §A.4 — the index-pack
//! offset table, delta resolution and `.idx` write of G3 build on this).
//!
//! # Why from scratch (dependency policy exception (a), docs §A.1.3)
//!
//! The only maintained pack implementation, `gix-pack`, is std-only
//! (pulls `gix-tempfile`/`parking_lot`); no `no_std` pack codec exists
//! on crates.io. The format is fully specified by git's pack-format
//! page, so this crate implements it as a bounded, checked parser with
//! adversarial tests — exactly the shape the project's parser rule
//! demands. The two primitives it needs come from the reviewed crates
//! of docs/git-ssh-deps.md §A.1 (dependency probes recorded in the
//! G3a commit):
//!
//! - **`sha1` 0.11** (`default-features = false`) — object ids and the
//!   pack trailer. `#![no_std]` unconditionally; verified building for
//!   `x86_64-unknown-none`.
//! - **`miniz_oxide` 0.9** (`default-features = false, features =
//!   ["with-alloc"]`) — inflate for the per-object zlib streams. The
//!   default feature set is already `no_std`+`alloc` (`std` is opt-in);
//!   the probe verified the target build. Fixtures in the tests use its
//!   deflate (test-only).
//!
//! No hand-rolled crypto: SHA-1 and DEFLATE are both crate-provided.
//!
//! # Scope (v1, documented decisions)
//!
//! - **Pack format v2 only** — v1/v3 headers are refused
//!   ([`Error::UnsupportedVersion`]).
//! - **Read-only decode**: header → per-object zlib streams → delta
//!   resolution → [`Object`]s in pack order. The 20-byte SHA-1 trailer
//!   must match the bytes before it (fail-closed, checked before any
//!   object is trusted).
//! - **Thin packs are refused** ([`Error::ThinPack`]): a `REF_DELTA`
//!   whose base is not an object of *this* pack is out of scope for v1
//!   (per docs/git-ssh-deps.md fetch notes — the server is asked for a
//!   full pack); it is reported, never guessed at.
//! - **Caps** ([`Limits`]): 16 MiB per object, 256 MiB of decompressed
//!   output in total, delta chains ≤ 50 deep, and an object count that
//!   cannot exceed what the input size can hold (≥ 9 bytes/object floor:
//!   1 header byte + the smallest possible 8-byte zlib stream) — so a
//!   `count` of 10⁹ in a 100-byte file fails before anything is
//!   allocated. Every cap is checked **before** the corresponding
//!   allocation.
//!
//! # Cycle handling
//!
//! `OFS_DELTA` bases always point strictly *earlier* in the pack (the
//! base position is `header_pos - offset` and must land on a previously
//! parsed object start, else [`Error::OfsOutOfRange`]), so offset chains
//! are acyclic by construction and are walked with a depth counter
//! ([`Error::DeltaChainTooDeep`]). A pack whose `REF_DELTA`s reference
//! each other in a loop can never resolve: the fixpoint stalls with
//! leftovers, and the stall is classified by comparing each leftover's
//! declared *base size* against the other leftovers' declared *result
//! sizes* — a consistent loop always matches (→ [`Error::DeltaCycle`]),
//! a lone `REF_DELTA` with an absent base never does (→
//! [`Error::ThinPack`]). Both are hard errors; nothing here can hang:
//! resolution is an iterative worklist, never unbounded recursion.
//!
//! Every path is `#![forbid(unsafe_code)]`, `#![no_std]`, uses checked
//! arithmetic on offsets/lengths derived from the pack, and is fed
//! hostile inputs in the test suite (truncation at every byte boundary,
//! bad magic/version/type, absurd counts, corrupt zlib, oversized
//! varints, out-of-bounds deltas, thin packs, delta loops, chain
//! overflow, trailer mismatch).

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
extern crate std;

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use miniz_oxide::inflate::TINFLStatus;
use miniz_oxide::inflate::core::{DecompressorOxide, decompress, inflate_flags};
use sha1::{Digest, Sha1};

/// The four-byte packfile signature.
pub const PACK_MAGIC: [u8; 4] = *b"PACK";
/// The only pack version this crate accepts.
pub const PACK_VERSION: u32 = 2;

/// Fixed header length: magic + version + object count (4 bytes each).
const HEADER_LEN: usize = 12;
/// Fixed trailer length: SHA-1 of everything before it.
const TRAILER_LEN: usize = 20;
/// Lowest possible byte cost of one stored object: a one-byte
/// object header (type + 4-bit size, no continuation) plus the
/// smallest possible zlib stream (2-byte CMF/FLG + a 2-byte empty
/// fixed-Huffman final block + 4-byte adler32 = 8). Used to refuse an
/// object count the input cannot possibly hold.
const MIN_BYTES_PER_OBJECT: u64 = 9;

/// Why a pack was refused. Fail-closed: an error means the whole pack
/// is discarded — nothing is partially decoded or "best effort".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input ends before a complete structure (header, object
    /// header, zlib stream, or a pack shorter than header + trailer).
    Truncated,
    /// The first four bytes are not `PACK`.
    BadMagic,
    /// The version field is not 2 (v1 and v3 are refused by design).
    UnsupportedVersion(u32),
    /// The declared object count cannot fit in the input size (see
    /// [`MIN_BYTES_PER_OBJECT`]) — refused before any allocation.
    AbsurdObjectCount,
    /// The SHA-1 of the bytes before the trailing 20 does not match
    /// the trailing 20 bytes.
    TrailerMismatch,
    /// A 3-bit object type of 0 (invalid) or 5 (reserved), or any
    /// value outside {1,2,3,4,6,7}.
    UnknownType(u8),
    /// A size/offset varint exceeds 64 bits (or its biased offset
    /// encoding overflows) — the pack is malformed, not merely large.
    SizeOverflow,
    /// A single object's declared size (or a delta's declared result
    /// size) exceeds [`Limits::max_object_size`].
    ObjectTooLarge,
    /// The running total of decompressed bytes would exceed
    /// [`Limits::max_total_output`] (zip-bomb guard).
    TotalTooLarge,
    /// The zlib stream is corrupt, fails its adler32, or produces a
    /// byte count other than the size declared in the object header.
    CorruptZlib,
    /// Bytes remain between the last declared object and the trailer.
    TrailingGarbage,
    /// An `OFS_DELTA` base position is before the pack header, inside
    /// another object, or not at a previously seen object start (this
    /// also covers a self-referencing offset of 0).
    OfsOutOfRange,
    /// The delta instruction stream is malformed: reserved `0x00`
    /// opcode, declared base size ≠ actual base length, copy/insert
    /// out of bounds of base or result, result not produced in full,
    /// or trailing bytes after the result is complete.
    DeltaMalformed,
    /// A `REF_DELTA` names a base object that is not in this pack —
    /// a thin pack, refused in v1 (see the crate docs).
    ThinPack,
    /// The pack's deltas reference each other in a loop (see the crate
    /// docs for how a stalled resolution is classified).
    DeltaCycle,
    /// A delta chain is deeper than [`Limits::max_delta_chain`].
    DeltaChainTooDeep,
}

/// A decoded object: its type and **decompressed** content, in pack
/// order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// The object's type (a delta resolves to its base's type).
    pub kind: Kind,
    /// The full, decompressed object content.
    pub data: Vec<u8>,
}

impl Object {
    /// The git object id: SHA-1 over `"<type> <len>\0<data>"`.
    pub fn oid(&self) -> [u8; 20] {
        object_id(self.kind, &self.data)
    }
}

/// The four object types a pack can ultimately hold (delta types 6/7
/// are representations, not types — they resolve to their base's
/// [`Kind`]).
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
    /// Map a pack type byte (1..=4) to a kind.
    pub fn from_type_byte(byte: u8) -> Option<Kind> {
        match byte {
            1 => Some(Kind::Commit),
            2 => Some(Kind::Tree),
            3 => Some(Kind::Blob),
            4 => Some(Kind::Tag),
            _ => None,
        }
    }

    /// The type name as git spells it in the object-id preimage.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Tree => "tree",
            Kind::Blob => "blob",
            Kind::Tag => "tag",
        }
    }
}

/// Git object id: SHA-1 over `"<type> <len>\0<data>"` (the loose-object
/// framing from git's object format).
pub fn object_id(kind: Kind, data: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(kind.as_str().as_bytes());
    hasher.update(b" ");
    // Decimal length without formatting into an allocation.
    let mut lenbuf = [0u8; 20];
    let mut i = 20;
    let mut n = data.len();
    if n == 0 {
        i = 19;
        lenbuf[19] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            lenbuf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    hasher.update(&lenbuf[i..]);
    hasher.update(b"\0");
    hasher.update(data);
    let digest = hasher.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(digest.as_slice());
    oid
}

/// Hard limits applied by [`decode_with_limits`]. Every cap is checked
/// **before** the allocation it bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Per-object cap on decompressed bytes: object content *and*
    /// delta result size (default 16 MiB).
    pub max_object_size: usize,
    /// Cap on the running total of decompressed bytes held while
    /// decoding (default 256 MiB) — bounds a zip-bomb pack whose
    /// per-object sizes are all legal.
    pub max_total_output: usize,
    /// Maximum delta chain depth (default 50).
    pub max_delta_chain: usize,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_object_size: 16 * 1024 * 1024,
            max_total_output: 256 * 1024 * 1024,
            max_delta_chain: 50,
        }
    }
}

/// Result of feeding bytes to [`parse_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderStep {
    /// Need more bytes (feed again).
    Incomplete,
    /// The 12-byte pack header parsed; version is validated (always 2
    /// here) and `count` is the declared object count.
    Done {
        /// Declared object count.
        count: u32,
    },
    /// The header is malformed — stop.
    Failed(Error),
}

/// Decode the 12-byte pack header at the front of `buf`. Strict: four
/// `PACK` bytes, then version 2 (anything else →
/// [`Error::UnsupportedVersion`]), then the object count. Feed
/// byte-at-byte: every proper prefix is `Incomplete` (the tests do).
pub fn parse_header(buf: &[u8]) -> HeaderStep {
    if buf.len() < 4 {
        return HeaderStep::Incomplete;
    }
    if buf.get(..4) != Some(PACK_MAGIC.as_slice()) {
        return HeaderStep::Failed(Error::BadMagic);
    }
    if buf.len() < 8 {
        return HeaderStep::Incomplete;
    }
    let version_bytes = match buf.get(4..8).and_then(|s| <[u8; 4]>::try_from(s).ok()) {
        Some(b) => b,
        None => return HeaderStep::Incomplete,
    };
    let version = u32::from_be_bytes(version_bytes);
    if version != PACK_VERSION {
        return HeaderStep::Failed(Error::UnsupportedVersion(version));
    }
    if buf.len() < 12 {
        return HeaderStep::Incomplete;
    }
    let count_bytes = match buf.get(8..12).and_then(|s| <[u8; 4]>::try_from(s).ok()) {
        Some(b) => b,
        None => return HeaderStep::Incomplete,
    };
    HeaderStep::Done {
        count: u32::from_be_bytes(count_bytes),
    }
}

/// The base reference of an object header: none (a full object), a
/// negative relative offset (`OFS_DELTA`), or a 20-byte base object id
/// (`REF_DELTA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRef {
    /// Full (non-delta) object.
    None,
    /// `OFS_DELTA`: biased base-128 offset as stored (the *position*
    /// is resolved against the pack during [`decode`]).
    Ofs(u64),
    /// `REF_DELTA`: base object id.
    Ref([u8; 20]),
}

/// A parsed object header (type/size varint plus base reference) —
/// *not* the zlib stream that follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjHeader {
    /// Raw 3-bit type (1..=4 full, 6 ofs-delta, 7 ref-delta).
    pub type_byte: u8,
    /// Declared size: uncompressed content size for full objects,
    /// uncompressed *delta data* size for deltas (pack-format).
    pub size: u64,
    /// Base reference (validated for type/encoding, not yet against
    /// the pack — that needs positions, done in [`decode`]).
    pub base: BaseRef,
    /// Bytes consumed from the front of the fed buffer.
    pub consumed: usize,
}

/// Result of feeding bytes to [`parse_object_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjHeaderStep {
    /// Need more bytes (feed again).
    Incomplete,
    /// One complete object header.
    Done(ObjHeader),
    /// The header is malformed — stop.
    Failed(Error),
}

/// Decode one object header (size varint + base reference) at the
/// front of `buf`. Strict: reserved/invalid types are refused, size
/// varints that exceed 64 bits are refused, and every proper prefix is
/// `Incomplete` (the tests feed these byte-at-byte).
pub fn parse_object_header(buf: &[u8]) -> ObjHeaderStep {
    let Some(&first) = buf.first() else {
        return ObjHeaderStep::Incomplete;
    };
    let type_byte = (first >> 4) & 0x07;
    if !matches!(type_byte, 1 | 2 | 3 | 4 | 6 | 7) {
        return ObjHeaderStep::Failed(Error::UnknownType(type_byte));
    }
    // Size: 4 bits from the first byte, then 7 bits per continuation.
    let mut size: u64 = (first & 0x0f) as u64;
    let mut shift = 4u32;
    let mut pos = 1usize;
    let mut cont = first & 0x80 != 0;
    while cont {
        let Some(&byte) = buf.get(pos) else {
            return ObjHeaderStep::Incomplete;
        };
        pos += 1;
        let chunk = (byte & 0x7f) as u64;
        if shift >= 64 || chunk > (u64::MAX >> shift) {
            return ObjHeaderStep::Failed(Error::SizeOverflow);
        }
        size |= chunk << shift;
        shift += 7;
        cont = byte & 0x80 != 0;
    }
    let base = match type_byte {
        6 => {
            // git's biased base-128 offset encoding: first byte gives
            // 7 bits, each continuation does offset = ((offset + 1)
            // << 7) | next7 (pack-format's "+2^7 + 2^14 + …").
            let Some(&b0) = buf.get(pos) else {
                return ObjHeaderStep::Incomplete;
            };
            pos += 1;
            let mut offset = (b0 & 0x7f) as u64;
            let mut ctrl = b0;
            while ctrl & 0x80 != 0 {
                let Some(&byte) = buf.get(pos) else {
                    return ObjHeaderStep::Incomplete;
                };
                pos += 1;
                let bumped = match offset.checked_add(1) {
                    Some(v) => v,
                    None => return ObjHeaderStep::Failed(Error::SizeOverflow),
                };
                if bumped > (u64::MAX >> 7) {
                    return ObjHeaderStep::Failed(Error::SizeOverflow);
                }
                offset = (bumped << 7) | (byte & 0x7f) as u64;
                ctrl = byte;
            }
            BaseRef::Ofs(offset)
        }
        7 => {
            if buf.len().saturating_sub(pos) < 20 {
                return ObjHeaderStep::Incomplete;
            }
            let mut oid = [0u8; 20];
            // Range proven above; copy keeps us off direct indexing.
            match buf.get(pos..pos + 20) {
                Some(bytes) => oid.copy_from_slice(bytes),
                None => return ObjHeaderStep::Incomplete,
            }
            pos += 20;
            BaseRef::Ref(oid)
        }
        _ => BaseRef::None,
    };
    ObjHeaderStep::Done(ObjHeader {
        type_byte,
        size,
        base,
        consumed: pos,
    })
}

/// One parsed object, before/while/after resolution.
struct Entry {
    /// Absolute pack position of the object's type byte.
    pos: u64,
    /// `Some` once the entry is fully resolved (always `Some` for
    /// full objects, set when a delta's content is produced).
    kind: Option<Kind>,
    /// Base reference with the OFS position already resolved against
    /// the pack (validated at parse time).
    base: BaseRef,
    /// Full object content (resolved entries) or the raw delta data
    /// (unresolved deltas; replaced by the content on resolution).
    data: Vec<u8>,
    /// Delta chain depth (0 for full objects).
    depth: usize,
    /// Parsed delta header (delta entries only).
    delta: Option<DeltaHeader>,
}

impl Entry {
    fn is_resolved(&self) -> bool {
        self.kind.is_some()
    }
}

/// The two size varints at the front of a delta stream plus the byte
/// offset where the instruction stream starts.
#[derive(Debug, Clone, Copy)]
struct DeltaHeader {
    /// Declared base content length (must equal the base's real
    /// length when applied).
    base_size: u64,
    /// Declared result content length (capped at parse time).
    result_size: u64,
    /// Offset of the first instruction in the delta data.
    instr_start: usize,
}

/// Parse the delta stream's two size varints.
fn parse_delta_header(data: &[u8]) -> Result<DeltaHeader, Error> {
    let mut pos = 0usize;
    let base_size = read_varint(data, &mut pos)?;
    let result_size = read_varint(data, &mut pos)?;
    Ok(DeltaHeader {
        base_size,
        result_size,
        instr_start: pos,
    })
}

/// 7-bit little-endian varint (git's "size encoding"). Exhaustion of
/// the buffer is a malformed delta; a value past 64 bits is
/// [`Error::SizeOverflow`].
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    loop {
        let Some(&byte) = buf.get(*pos) else {
            return Err(Error::DeltaMalformed);
        };
        *pos += 1;
        let chunk = (byte & 0x7f) as u64;
        if shift >= 64 || chunk > (u64::MAX >> shift) {
            return Err(Error::SizeOverflow);
        }
        value |= chunk << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
}

/// Apply a git delta instruction stream: produce the result content
/// from `base`. Every read of `delta` and every slice bound is
/// checked; the result is allocated only after the declared size has
/// been validated against both caps.
fn apply_delta(
    base: &[u8],
    delta: &[u8],
    dh: &DeltaHeader,
    limits: &Limits,
    total: &mut usize,
) -> Result<Vec<u8>, Error> {
    if dh.base_size != base.len() as u64 {
        return Err(Error::DeltaMalformed);
    }
    let result_size = usize::try_from(dh.result_size).map_err(|_| Error::ObjectTooLarge)?;
    if result_size > limits.max_object_size {
        return Err(Error::ObjectTooLarge);
    }
    if total
        .checked_add(result_size)
        .is_none_or(|t| t > limits.max_total_output)
    {
        return Err(Error::TotalTooLarge);
    }
    let mut out = Vec::new();
    out.try_reserve(result_size)
        .map_err(|_| Error::TotalTooLarge)?;
    let mut pos = dh.instr_start;
    let mut written = 0usize;
    while written < result_size {
        let Some(&cmd) = delta.get(pos) else {
            return Err(Error::DeltaMalformed);
        };
        pos += 1;
        if cmd & 0x80 != 0 {
            // Copy from base: up to 4 offset bytes (bits 0..=3) and
            // up to 3 size bytes (bits 4..=6), little-endian; absent
            // bytes mean 0, and a size of 0 means 0x10000.
            let mut offset: u64 = 0;
            for i in 0..4 {
                if cmd & (1 << i) != 0 {
                    let Some(&byte) = delta.get(pos) else {
                        return Err(Error::DeltaMalformed);
                    };
                    pos += 1;
                    offset |= (byte as u64) << (8 * i);
                }
            }
            let mut size: u64 = 0;
            for i in 0..3 {
                if cmd & (1 << (4 + i)) != 0 {
                    let Some(&byte) = delta.get(pos) else {
                        return Err(Error::DeltaMalformed);
                    };
                    pos += 1;
                    size |= (byte as u64) << (8 * i);
                }
            }
            if size == 0 {
                size = 0x10000;
            }
            let end = offset.checked_add(size).ok_or(Error::DeltaMalformed)?;
            if end > base.len() as u64 {
                return Err(Error::DeltaMalformed);
            }
            let src = base
                .get(
                    usize::try_from(offset).map_err(|_| Error::DeltaMalformed)?
                        ..usize::try_from(end).map_err(|_| Error::DeltaMalformed)?,
                )
                .ok_or(Error::DeltaMalformed)?;
            let copy_len = src.len();
            written = written.checked_add(copy_len).ok_or(Error::DeltaMalformed)?;
            if written > result_size {
                return Err(Error::DeltaMalformed);
            }
            out.extend_from_slice(src);
        } else if cmd == 0 {
            // Reserved opcode (pack-format).
            return Err(Error::DeltaMalformed);
        } else {
            // Insert the next `cmd` (1..=127) bytes verbatim.
            let n = cmd as usize;
            let end = pos.checked_add(n).ok_or(Error::DeltaMalformed)?;
            let src = delta.get(pos..end).ok_or(Error::DeltaMalformed)?;
            pos = end;
            written = written.checked_add(n).ok_or(Error::DeltaMalformed)?;
            if written > result_size {
                return Err(Error::DeltaMalformed);
            }
            out.extend_from_slice(src);
        }
    }
    // The instruction stream must be consumed exactly.
    if pos != delta.len() {
        return Err(Error::DeltaMalformed);
    }
    *total += result_size;
    Ok(out)
}

/// Inflate one zlib stream from the front of `input`, expecting
/// exactly `declared` decompressed bytes (the size from the object
/// header). Returns the content and the number of input bytes the
/// stream consumed, so the caller can advance to the next object.
fn inflate_exact(input: &[u8], declared: usize) -> Result<(Vec<u8>, usize), Error> {
    let mut out = Vec::new();
    out.try_reserve(declared)
        .map_err(|_| Error::TotalTooLarge)?;
    out.resize(declared, 0);
    let mut decompressor = DecompressorOxide::new();
    let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
        | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
    let (status, in_consumed, out_consumed) =
        decompress(&mut decompressor, input, &mut out, 0, flags);
    if in_consumed > input.len() {
        return Err(Error::CorruptZlib);
    }
    match status {
        TINFLStatus::Done if out_consumed == declared => Ok((out, in_consumed)),
        // The stream ended but produced a different byte count than
        // the object header declared — fail closed.
        TINFLStatus::Done => Err(Error::CorruptZlib),
        // Input exhausted mid-stream (the slice already stops at the
        // trailer, so this is a cut stream, not a short read).
        TINFLStatus::NeedsMoreInput | TINFLStatus::FailedCannotMakeProgress => {
            Err(Error::Truncated)
        }
        // Output larger than declared, bad parameters, adler32
        // mismatch, corrupt deflate data.
        _ => Err(Error::CorruptZlib),
    }
}

/// A minimal **sha1 → pack offset** index: the in-memory shape of a
/// `.idx` v2 main table, built as a side effect of decoding (every
/// object's id is computed exactly once on the resolution queue) and
/// exposed for G3's index-pack. Iteration is oid-sorted ([`BTreeMap`]
/// order), which is the order a `.idx` needs. Duplicate object
/// contents collapse to the last offset (a real repo has no duplicate
/// objects; a hostile one is still decoded correctly — only the index
/// is affected).
#[derive(Debug, Clone, Default)]
pub struct PackIndex {
    map: BTreeMap<[u8; 20], u64>,
}

impl PackIndex {
    /// An empty index.
    pub fn new() -> PackIndex {
        PackIndex::default()
    }

    /// Record `oid → offset` (last write wins on duplicates).
    pub fn insert(&mut self, oid: [u8; 20], offset: u64) {
        self.map.insert(oid, offset);
    }

    /// The pack offset of `oid`, if indexed.
    pub fn get(&self, oid: &[u8; 20]) -> Option<u64> {
        self.map.get(oid).copied()
    }

    /// Number of indexed objects.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when no object is indexed.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Iterate `(oid, offset)` in ascending oid order (the `.idx`
    /// main-table order).
    pub fn iter(&self) -> impl Iterator<Item = ([u8; 20], u64)> + '_ {
        self.map.iter().map(|(&oid, &offset)| (oid, offset))
    }
}

/// Mutable state of one decode run: entries plus the indexes and
/// dependents that drive resolution.
struct Decoder<'a> {
    entries: Vec<Entry>,
    limits: &'a Limits,
    /// Object-header position → entry index (OFS base lookup).
    pos_map: BTreeMap<u64, usize>,
    /// Resolved object id → entry index (REF base lookup). Inserted
    /// only when an entry's content is final, so presence implies
    /// resolution.
    oid_map: BTreeMap<[u8; 20], usize>,
    /// Base position → OFS deltas waiting on it.
    ofs_deps: BTreeMap<u64, Vec<usize>>,
    /// Declared base id → REF deltas waiting on it.
    ref_deps: BTreeMap<[u8; 20], Vec<usize>>,
    /// Running total of decompressed bytes (see [`Limits::max_total_output`]).
    total: usize,
    /// Entries whose resolution should notify their dependents next.
    queue: VecDeque<usize>,
    /// sha1 → offset of every resolved object (see [`PackIndex`]).
    index: PackIndex,
}

impl Decoder<'_> {
    /// Try to resolve one delta. `Ok(())` means either "resolved" or
    /// "base not ready yet" (the dependent is notified when the base
    /// resolves); `Err` is a hard failure of the pack.
    fn try_resolve(&mut self, idx: usize) -> Result<(), Error> {
        let entry = match self.entries.get(idx) {
            Some(e) => e,
            None => return Err(Error::Truncated),
        };
        if entry.is_resolved() {
            return Ok(());
        }
        let base_idx = match entry.base {
            BaseRef::Ofs(pos) => match self.pos_map.get(&pos) {
                Some(&b) => b,
                None => return Err(Error::OfsOutOfRange),
            },
            BaseRef::Ref(oid) => match self.oid_map.get(&oid) {
                Some(&b) => b,
                // Base unknown (absent from the pack, or an unresolved
                // delta whose id is not computable yet) — wait for a
                // notification or classify at the stall.
                None => return Ok(()),
            },
            BaseRef::None => return Ok(()),
        };
        let base_entry = match self.entries.get(base_idx) {
            Some(e) if e.is_resolved() => e,
            // Not ready yet; the base's resolution notifies us.
            Some(_) => return Ok(()),
            None => return Err(Error::OfsOutOfRange),
        };
        let depth = base_entry.depth.saturating_add(1);
        if depth > self.limits.max_delta_chain {
            return Err(Error::DeltaChainTooDeep);
        }
        let base_kind = base_entry.kind.ok_or(Error::DeltaMalformed)?;
        let result = {
            let base = self.entries.get(base_idx).ok_or(Error::OfsOutOfRange)?;
            let entry = self.entries.get(idx).ok_or(Error::Truncated)?;
            let dh = entry.delta.as_ref().ok_or(Error::DeltaMalformed)?;
            apply_delta(&base.data, &entry.data, dh, self.limits, &mut self.total)?
        };
        let oid = {
            let entry = self.entries.get_mut(idx).ok_or(Error::Truncated)?;
            entry.data = result;
            entry.kind = Some(base_kind);
            entry.depth = depth;
            entry.delta = None;
            // Index the freshly resolved id: a REF delta woken by the
            // notification below looks its base up in oid_map.
            object_id(base_kind, &entry.data)
        };
        self.oid_map.insert(oid, idx);
        self.queue.push_back(idx);
        Ok(())
    }

    /// Process the notification queue: every resolved entry wakes the
    /// deltas that named its position (OFS) or its id (REF), and lands
    /// in the sha1 → offset index.
    fn drain(&mut self) -> Result<(), Error> {
        while let Some(idx) = self.queue.pop_front() {
            let (pos, oid) = match self.entries.get(idx) {
                Some(e) => (e.pos, e.kind.map(|kind| object_id(kind, &e.data))),
                None => return Err(Error::Truncated),
            };
            if let Some(oid) = oid {
                self.index.insert(oid, pos);
            }
            let ofs_waiters = self.ofs_deps.remove(&pos).unwrap_or_default();
            for waiter in ofs_waiters {
                self.try_resolve(waiter)?;
            }
            if let Some(oid) = oid {
                let ref_waiters = self.ref_deps.remove(&oid).unwrap_or_default();
                for waiter in ref_waiters {
                    self.try_resolve(waiter)?;
                }
            }
        }
        Ok(())
    }
}

/// Decode a complete packfile with the default [`Limits`].
///
/// # Errors
///
/// Every [`Error`] variant — decoding is fail-closed: any malformed,
/// hostile, or out-of-scope pack is refused as a whole.
pub fn decode(pack: &[u8]) -> Result<Vec<Object>, Error> {
    decode_core(pack, &Limits::default()).map(|(objects, _)| objects)
}

/// Like [`decode`], but also returns the sha1 → offset [`PackIndex`]
/// built while resolving (the in-memory `.idx` main table; see
/// [`PackIndex`]).
pub fn decode_with_index(pack: &[u8]) -> Result<(Vec<Object>, PackIndex), Error> {
    decode_core(pack, &Limits::default())
}

/// Decode a complete packfile under caller-supplied [`Limits`] (the
/// tests use small caps to exercise them cheaply).
///
/// Order of checks: length → header (magic/version) → trailer SHA-1 →
/// count bound → per-object parse (type, size caps, zlib, OFS base
/// positions) → exact body consumption → delta resolution worklist →
/// stall classification → objects in pack order.
pub fn decode_with_limits(pack: &[u8], limits: &Limits) -> Result<Vec<Object>, Error> {
    decode_core(pack, limits).map(|(objects, _)| objects)
}

fn decode_core(pack: &[u8], limits: &Limits) -> Result<(Vec<Object>, PackIndex), Error> {
    if pack.len() < HEADER_LEN + TRAILER_LEN {
        return Err(Error::Truncated);
    }
    let count = match parse_header(pack) {
        HeaderStep::Done { count } => u64::from(count),
        HeaderStep::Failed(e) => return Err(e),
        // Unreachable: the length check above guarantees 12 bytes.
        HeaderStep::Incomplete => return Err(Error::Truncated),
    };
    let body_end = pack.len() - TRAILER_LEN;
    let body = pack.get(..body_end).ok_or(Error::Truncated)?;
    let trailer = pack.get(body_end..).ok_or(Error::Truncated)?;
    let digest = Sha1::digest(body);
    if digest.as_slice() != trailer {
        return Err(Error::TrailerMismatch);
    }
    // Refuse counts the input cannot hold before allocating anything.
    if count > (body.len() as u64) / MIN_BYTES_PER_OBJECT {
        return Err(Error::AbsurdObjectCount);
    }

    let mut entries: Vec<Entry> = Vec::new();
    let mut pos_map: BTreeMap<u64, usize> = BTreeMap::new();
    let mut oid_map: BTreeMap<[u8; 20], usize> = BTreeMap::new();
    let mut ofs_deps: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    let mut ref_deps: BTreeMap<[u8; 20], Vec<usize>> = BTreeMap::new();
    let mut total: usize = 0;
    let mut pos = HEADER_LEN;

    for _ in 0..count {
        let slice = pack.get(pos..body_end).ok_or(Error::Truncated)?;
        let hdr = match parse_object_header(slice) {
            ObjHeaderStep::Done(h) => h,
            ObjHeaderStep::Failed(e) => return Err(e),
            ObjHeaderStep::Incomplete => return Err(Error::Truncated),
        };
        let entry_pos = pos as u64;
        pos = pos.checked_add(hdr.consumed).ok_or(Error::Truncated)?;

        // Caps before any allocation.
        if hdr.size > limits.max_object_size as u64 {
            return Err(Error::ObjectTooLarge);
        }
        let declared = usize::try_from(hdr.size).map_err(|_| Error::ObjectTooLarge)?;
        if total
            .checked_add(declared)
            .is_none_or(|t| t > limits.max_total_output)
        {
            return Err(Error::TotalTooLarge);
        }

        // Resolve the OFS base position against the pack: strictly
        // earlier, at/after the header end, and on a real object start
        // (pos_map holds only previously parsed objects — which also
        // rejects a self-referencing offset of 0).
        let base = match hdr.base {
            BaseRef::Ofs(offset) => {
                let base_pos = entry_pos
                    .checked_sub(offset)
                    .filter(|&p| p >= HEADER_LEN as u64)
                    .ok_or(Error::OfsOutOfRange)?;
                if !pos_map.contains_key(&base_pos) {
                    return Err(Error::OfsOutOfRange);
                }
                BaseRef::Ofs(base_pos)
            }
            other => other,
        };

        let slice = pack.get(pos..body_end).ok_or(Error::Truncated)?;
        let (stored, used) = inflate_exact(slice, declared)?;
        pos = pos.checked_add(used).ok_or(Error::Truncated)?;
        total = total.checked_add(declared).ok_or(Error::TotalTooLarge)?;

        let is_delta = matches!(base, BaseRef::Ofs(_) | BaseRef::Ref(_));
        let (kind, delta) = if is_delta {
            let dh = parse_delta_header(&stored)?;
            if dh.result_size > limits.max_object_size as u64 {
                return Err(Error::ObjectTooLarge);
            }
            (None, Some(dh))
        } else {
            let kind =
                Kind::from_type_byte(hdr.type_byte).ok_or(Error::UnknownType(hdr.type_byte))?;
            (Some(kind), None)
        };

        let idx = entries.len();
        entries.push(Entry {
            pos: entry_pos,
            kind,
            base,
            data: stored,
            depth: 0,
            delta,
        });
        pos_map.insert(entry_pos, idx);
        if let Some(kind) = entries[idx].kind {
            // Full objects are resolved at parse time: index their id
            // so REF deltas can base on them (invariant: presence in
            // oid_map implies the entry is resolved).
            let oid = object_id(kind, &entries[idx].data);
            oid_map.insert(oid, idx);
        }
        match base {
            BaseRef::Ofs(base_pos) => {
                ofs_deps.entry(base_pos).or_default().push(idx);
            }
            BaseRef::Ref(oid) => {
                ref_deps.entry(oid).or_default().push(idx);
            }
            BaseRef::None => {}
        }
    }
    if pos != body_end {
        return Err(Error::TrailingGarbage);
    }

    // Phase 1: worklist fixpoint. Full objects start queued; resolving
    // an entry notifies exactly the deltas waiting on it, so every
    // acyclic pack resolves here in O(n log n).
    let mut queue: VecDeque<usize> = VecDeque::new();
    for (idx, entry) in entries.iter().enumerate() {
        if entry.is_resolved() {
            queue.push_back(idx);
        }
    }
    let mut decoder = Decoder {
        entries,
        limits,
        pos_map,
        oid_map,
        ofs_deps,
        ref_deps,
        total,
        queue,
        index: PackIndex::new(),
    };
    loop {
        decoder.drain()?;
        let mut progress = false;
        for idx in 0..decoder.entries.len() {
            if !decoder.entries[idx].is_resolved() {
                decoder.try_resolve(idx)?;
                if decoder.entries[idx].is_resolved() {
                    progress = true;
                }
            }
        }
        if !progress {
            break;
        }
    }

    // Phase 2: anything still unresolved can never resolve — classify
    // the stall and refuse the pack.
    let leftovers: Vec<usize> = decoder
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.is_resolved())
        .map(|(i, _)| i)
        .collect();
    if !leftovers.is_empty() {
        // An OFS chain always bottoms out at a REF base (OFS bases
        // point strictly earlier and were validated at parse time), so
        // a leftover without a REF base is unreachable — fail closed.
        let mut sizes: BTreeMap<u64, usize> = BTreeMap::new();
        for &i in &leftovers {
            if let Some(dh) = decoder.entries[i].delta {
                *sizes.entry(dh.result_size).or_insert(0) += 1;
            }
        }
        for &i in &leftovers {
            let entry = &decoder.entries[i];
            if matches!(entry.base, BaseRef::Ref(_)) {
                let Some(dh) = entry.delta else {
                    continue;
                };
                // If this delta's base were in the pack, some other
                // leftover would have to *be* it — and its result size
                // would equal our declared base size. No such
                // candidate ⇒ the base is genuinely absent.
                let mut candidates = sizes.get(&dh.base_size).copied().unwrap_or(0);
                if dh.result_size == dh.base_size {
                    candidates = candidates.saturating_sub(1); // not ourselves
                }
                if candidates == 0 {
                    return Err(Error::ThinPack);
                }
            }
        }
        // Every REF leftover has a size-consistent partner: a loop
        // (see the crate docs — a consistent loop always matches).
        return Err(Error::DeltaCycle);
    }

    // All resolved: emit in pack order.
    let mut out = Vec::new();
    for entry in decoder.entries {
        let kind = match entry.kind {
            Some(kind) => kind,
            // Unreachable: leftovers were refused above.
            None => return Err(Error::DeltaCycle),
        };
        out.push(Object {
            kind,
            data: entry.data,
        });
    }
    Ok((out, decoder.index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;
    use std::vec;

    // ------------------------------------------------------------------
    // pack builder (test-only): fixtures are built programmatically so
    // every hostile byte pattern below is constructed, not hard-coded.
    // ------------------------------------------------------------------

    /// What one fixture object looks like before serialization.
    struct ObjSpec {
        type_byte: u8,
        /// Bytes to zlib-compress (content for full objects, delta
        /// stream for deltas).
        payload: Vec<u8>,
        base: BaseSpec,
        /// Override the declared header size (hostile: mismatch with
        /// what the stream actually produces).
        declared_size: Option<u64>,
        /// Deflate level (0 = stored blocks, "uncompressed-ish").
        level: u8,
    }

    enum BaseSpec {
        None,
        /// `OFS_DELTA` to fixture object `idx` (offset computed from
        /// the real serialized positions).
        Ofs(usize),
        /// `OFS_DELTA` landing `skip` bytes into fixture object `idx`
        /// (hostile: not an object start).
        OfsInto {
            idx: usize,
            skip: usize,
        },
        /// `OFS_DELTA` with a literal stored offset (hostile values).
        OfsRaw(u64),
        /// `REF_DELTA` with a literal base id.
        Ref([u8; 20]),
    }

    struct BuiltPack {
        bytes: Vec<u8>,
        /// `(start, end)` of each object's zlib stream.
        streams: Vec<(usize, usize)>,
    }

    impl BuiltPack {
        /// Append the SHA-1 trailer over everything written so far.
        fn finish(mut self) -> Vec<u8> {
            let digest = Sha1::digest(&self.bytes);
            self.bytes.extend_from_slice(digest.as_slice());
            self.bytes
        }
    }

    /// git's biased base-128 offset encoding (inverse of the decoder
    /// in [`parse_object_header`]).
    fn put_ofs(out: &mut Vec<u8>, mut value: u64) {
        let mut tmp = [0u8; 12];
        let mut n = 0;
        loop {
            tmp[n] = (value & 0x7f) as u8;
            n += 1;
            if value < 128 {
                break;
            }
            value = (value >> 7) - 1;
        }
        // tmp[0] is the *last* stream byte; all but that one carry the
        // continuation bit.
        for i in (0..n).rev() {
            let mut byte = tmp[i];
            if i != 0 {
                byte |= 0x80;
            }
            out.push(byte);
        }
    }

    /// Plain 7-bit LE varint (delta size encoding).
    fn put_varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    /// Object-header size varint: 4 bits in the first byte with the
    /// type, then 7-bit continuations.
    fn put_obj_header(out: &mut Vec<u8>, type_byte: u8, size: u64) {
        let low = (size & 0x0f) as u8;
        let mut rest = size >> 4;
        let mut first = low | (type_byte << 4);
        if rest != 0 {
            first |= 0x80;
            out.push(first);
            loop {
                let mut byte = (rest & 0x7f) as u8;
                rest >>= 7;
                if rest != 0 {
                    byte |= 0x80;
                }
                out.push(byte);
                if rest == 0 {
                    break;
                }
            }
        } else {
            out.push(first);
        }
    }

    /// Delta whose instructions only insert (base never read — but the
    /// declared base size must still match when applied).
    fn delta_insert(base_len: u64, result: &[u8]) -> Vec<u8> {
        let mut d = Vec::new();
        put_varint(&mut d, base_len);
        put_varint(&mut d, result.len() as u64);
        for chunk in result.chunks(127) {
            d.push(chunk.len() as u8);
            d.extend_from_slice(chunk);
        }
        d
    }

    /// Delta that copies the whole base (a real base-dependent chain
    /// link).
    fn delta_copy_all(base_len: u64) -> Vec<u8> {
        let mut d = Vec::new();
        put_varint(&mut d, base_len);
        put_varint(&mut d, base_len);
        // Copy: offset 0 (no offset bytes), size = base_len in as few
        // size bytes as it takes.
        let mut cmd: u8 = 0x80;
        let mut size = base_len;
        let mut size_bytes = Vec::new();
        if size == 0 {
            // A size of 0 would mean 0x10000; empty bases never use
            // copy-all in these fixtures.
            size_bytes.push(0);
            cmd |= 0x10;
        } else {
            while size > 0 {
                size_bytes.push((size & 0xff) as u8);
                size >>= 8;
            }
            for i in 0..size_bytes.len() {
                cmd |= 1 << (4 + i);
            }
        }
        d.push(cmd);
        d.extend_from_slice(&size_bytes);
        d
    }

    fn build_pack(objs: &[ObjSpec]) -> BuiltPack {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_be_bytes());
        bytes.extend_from_slice(&(objs.len() as u32).to_be_bytes());
        let mut positions = Vec::new();
        let mut streams = Vec::new();
        for obj in objs {
            let pos = bytes.len();
            positions.push(pos);
            let size = obj.declared_size.unwrap_or(obj.payload.len() as u64);
            put_obj_header(&mut bytes, obj.type_byte, size);
            match &obj.base {
                BaseSpec::None => {}
                BaseSpec::Ofs(idx) => {
                    let offset = (pos - positions[*idx]) as u64;
                    put_ofs(&mut bytes, offset);
                }
                BaseSpec::OfsInto { idx, skip } => {
                    let offset = (pos - (positions[*idx] + skip)) as u64;
                    put_ofs(&mut bytes, offset);
                }
                BaseSpec::OfsRaw(offset) => put_ofs(&mut bytes, *offset),
                BaseSpec::Ref(oid) => bytes.extend_from_slice(oid),
            }
            let start = bytes.len();
            bytes.extend_from_slice(&miniz_oxide::deflate::compress_to_vec_zlib(
                &obj.payload,
                obj.level,
            ));
            streams.push((start, bytes.len()));
        }
        BuiltPack { bytes, streams }
    }

    fn full(type_byte: u8, data: &[u8]) -> ObjSpec {
        ObjSpec {
            type_byte,
            payload: data.to_vec(),
            base: BaseSpec::None,
            declared_size: None,
            level: 0,
        }
    }

    fn with_trailer(mut bytes: Vec<u8>) -> Vec<u8> {
        let digest = Sha1::digest(&bytes);
        bytes.extend_from_slice(digest.as_slice());
        bytes
    }

    // ------------------------------------------------------------------
    // header parsing (byte-at-a-time is this repo's signature style)
    // ------------------------------------------------------------------

    #[test]
    fn header_feeds_one_byte_at_a_time() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&PACK_MAGIC);
        hdr.extend_from_slice(&PACK_VERSION.to_be_bytes());
        hdr.extend_from_slice(&3u32.to_be_bytes());
        for split in 0..hdr.len() {
            assert_eq!(
                parse_header(&hdr[..split]),
                HeaderStep::Incomplete,
                "split {split} of {} must be incomplete",
                hdr.len()
            );
        }
        assert_eq!(parse_header(&hdr), HeaderStep::Done { count: 3 });
    }

    #[test]
    fn header_bad_magic_fails_at_four_bytes() {
        let mut hdr = Vec::new();
        hdr.extend_from_slice(b"XACK");
        hdr.extend_from_slice(&PACK_VERSION.to_be_bytes());
        hdr.extend_from_slice(&1u32.to_be_bytes());
        for split in 0..4 {
            assert_eq!(parse_header(&hdr[..split]), HeaderStep::Incomplete);
        }
        for split in 4..=hdr.len() {
            assert_eq!(
                parse_header(&hdr[..split]),
                HeaderStep::Failed(Error::BadMagic),
                "split {split}"
            );
        }
    }

    #[test]
    fn header_rejects_versions_one_and_three() {
        for bad in [1u32, 3] {
            let mut hdr = Vec::new();
            hdr.extend_from_slice(&PACK_MAGIC);
            hdr.extend_from_slice(&bad.to_be_bytes());
            hdr.extend_from_slice(&7u32.to_be_bytes());
            for split in 0..8 {
                assert_eq!(parse_header(&hdr[..split]), HeaderStep::Incomplete);
            }
            for split in 8..=hdr.len() {
                assert_eq!(
                    parse_header(&hdr[..split]),
                    HeaderStep::Failed(Error::UnsupportedVersion(bad)),
                    "version {bad}, split {split}"
                );
            }
        }
    }

    #[test]
    fn object_header_feeds_one_byte_at_a_time() {
        // Full object with a two-byte size varint (300 > 15).
        let mut full_hdr = Vec::new();
        put_obj_header(&mut full_hdr, 3, 300);
        assert_eq!(full_hdr.len(), 2);
        for split in 0..full_hdr.len() {
            assert_eq!(
                parse_object_header(&full_hdr[..split]),
                ObjHeaderStep::Incomplete
            );
        }
        match parse_object_header(&full_hdr) {
            ObjHeaderStep::Done(h) => {
                assert_eq!(
                    (h.type_byte, h.size, h.base, h.consumed),
                    (3, 300, BaseRef::None, 2)
                )
            }
            other => panic!("expected Done, got {other:?}"),
        }

        // OFS delta: size varint + biased offset varint (300 → 2 bytes).
        let mut ofs_hdr = Vec::new();
        put_obj_header(&mut ofs_hdr, 6, 40);
        put_ofs(&mut ofs_hdr, 300);
        assert_eq!(ofs_hdr.len(), 4);
        for split in 0..ofs_hdr.len() {
            assert_eq!(
                parse_object_header(&ofs_hdr[..split]),
                ObjHeaderStep::Incomplete
            );
        }
        match parse_object_header(&ofs_hdr) {
            ObjHeaderStep::Done(h) => {
                assert_eq!((h.type_byte, h.size, h.base), (6, 40, BaseRef::Ofs(300)))
            }
            other => panic!("expected Done, got {other:?}"),
        }

        // REF delta: size varint + 20-byte id.
        let mut ref_hdr = Vec::new();
        put_obj_header(&mut ref_hdr, 7, 10);
        let oid_start = ref_hdr.len();
        ref_hdr.extend_from_slice(&[0xAB; 20]);
        for split in 0..ref_hdr.len() {
            let step = parse_object_header(&ref_hdr[..split]);
            if split < oid_start {
                assert_eq!(step, ObjHeaderStep::Incomplete, "split {split}");
            } else {
                assert_eq!(step, ObjHeaderStep::Incomplete, "split {split} mid-oid");
            }
        }
        match parse_object_header(&ref_hdr) {
            ObjHeaderStep::Done(h) => {
                assert_eq!((h.type_byte, h.size), (7, 10));
                assert_eq!(h.base, BaseRef::Ref([0xAB; 20]));
                assert_eq!(h.consumed, ref_hdr.len());
            }
            other => panic!("expected Done, got {other:?}"),
        }
    }

    #[test]
    fn object_header_rejects_reserved_types() {
        for bad in [0u8, 5] {
            let mut hdr = Vec::new();
            put_obj_header(&mut hdr, bad, 3);
            assert_eq!(
                parse_object_header(&hdr),
                ObjHeaderStep::Failed(Error::UnknownType(bad))
            );
        }
    }

    #[test]
    fn object_header_size_varint_overflow() {
        // First byte: type commit + size low nibble + continuation,
        // then enough 0xFF continuation bytes to blow past 64 bits.
        let mut hdr = vec![0x9f]; // cont | type 1 | size 0xf
        hdr.extend_from_slice(&[0xff; 12]);
        assert_eq!(
            parse_object_header(&hdr),
            ObjHeaderStep::Failed(Error::SizeOverflow)
        );
    }

    // ------------------------------------------------------------------
    // happy paths
    // ------------------------------------------------------------------

    #[test]
    fn decode_three_objects_and_verify_oids() {
        let built = build_pack(&[
            {
                let mut o = full(1, b"tree-ish commit\n");
                o.level = 6; // real deflate, not just stored blocks
                o
            },
            full(2, b"\x00"),
            full(3, b"hello pack"),
        ]);
        let pack = built.finish();
        let objects = decode(&pack).expect("valid pack decodes");
        assert_eq!(objects.len(), 3);
        assert_eq!(objects[0].kind, Kind::Commit);
        assert_eq!(objects[1].kind, Kind::Tree);
        assert_eq!(objects[2].kind, Kind::Blob);
        assert_eq!(objects[0].data, b"tree-ish commit\n");
        assert_eq!(objects[2].data, b"hello pack");
        // Oids computed independently of `object_id`: raw framing.
        let expect = |kind: &str, data: &[u8]| -> [u8; 20] {
            let mut preimage = Vec::new();
            preimage.extend_from_slice(kind.as_bytes());
            preimage.push(b' ');
            preimage.extend_from_slice(data.len().to_string().as_bytes());
            preimage.push(0);
            preimage.extend_from_slice(data);
            let digest = Sha1::digest(&preimage);
            let mut oid = [0u8; 20];
            oid.copy_from_slice(digest.as_slice());
            oid
        };
        assert_eq!(objects[0].oid(), expect("commit", b"tree-ish commit\n"));
        assert_eq!(objects[2].oid(), expect("blob", b"hello pack"));
        // And against a git known vector: the empty blob.
        assert_eq!(
            object_id(Kind::Blob, b""),
            [
                0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b, 0x29, 0xae, 0x77, 0x5a,
                0xd8, 0xc2, 0xe4, 0x8c, 0x53, 0x91
            ]
        );
        // Empty tree (git's well-known constant).
        assert_eq!(
            object_id(Kind::Tree, b""),
            [
                0x4b, 0x82, 0x5d, 0xc6, 0x42, 0xcb, 0x6e, 0xb9, 0xa0, 0x60, 0xe5, 0x4b, 0xf8, 0xd6,
                0x92, 0x88, 0xfb, 0xee, 0x49, 0x04
            ]
        );
    }

    #[test]
    fn decode_zero_object_pack() {
        let pack = with_trailer({
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&PACK_MAGIC);
            bytes.extend_from_slice(&PACK_VERSION.to_be_bytes());
            bytes.extend_from_slice(&0u32.to_be_bytes());
            bytes
        });
        assert_eq!(pack.len(), HEADER_LEN + TRAILER_LEN);
        assert_eq!(decode(&pack), Ok(Vec::new()));
        // The index of an empty pack is empty too.
        let (_, index) = decode_with_index(&pack).expect("empty pack decodes");
        assert!(index.is_empty());
    }

    #[test]
    fn decode_empty_object_and_index_roundtrip() {
        // A zero-byte blob is a real git object: exercises the
        // zero-length inflate path and a one-object index.
        let built = build_pack(&[full(3, b""), full(1, b"x")]);
        let pack = built.finish();
        let (objects, index) = decode_with_index(&pack).expect("decodes");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].data.as_slice(), b"");
        assert_eq!(objects[0].oid(), object_id(Kind::Blob, b""));
        assert_eq!(index.len(), 2);
        // Offsets point at the real object starts (12 for the first).
        assert_eq!(index.get(&objects[0].oid()), Some(HEADER_LEN as u64));
        let second = index.get(&objects[1].oid()).expect("second indexed");
        assert!(second > HEADER_LEN as u64);
        // The index iterates in oid order and covers both objects.
        let oids: std::vec::Vec<[u8; 20]> = index.iter().map(|(oid, _)| oid).collect();
        assert_eq!(oids.len(), 2);
        let mut sorted = oids.clone();
        sorted.sort();
        assert_eq!(oids, sorted);
    }

    #[test]
    fn decode_empty_and_short_input() {
        assert_eq!(decode(&[]), Err(Error::Truncated));
        assert_eq!(decode(&[0u8; 20]), Err(Error::Truncated));
        // A full header but no room for the trailer.
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&PACK_MAGIC);
        hdr.extend_from_slice(&PACK_VERSION.to_be_bytes());
        hdr.extend_from_slice(&1u32.to_be_bytes());
        assert_eq!(decode(&hdr), Err(Error::Truncated));
    }

    #[test]
    fn zlib_stream_reports_exact_consumed_length() {
        // Isolate the miniz contract the whole sequential parse leans
        // on: `decompress` must stop at the adler32 and report exactly
        // the stream's byte count even with the next object's bytes
        // glued behind it.
        let data = b"stream boundary probe";
        let stream = miniz_oxide::deflate::compress_to_vec_zlib(data, 6);
        let mut input = stream.clone();
        input.extend_from_slice(b"NEXT-OBJECT-HEADER-BYTES");
        let mut out = vec![0u8; data.len()];
        let mut decompressor = DecompressorOxide::new();
        let flags = inflate_flags::TINFL_FLAG_PARSE_ZLIB_HEADER
            | inflate_flags::TINFL_FLAG_USING_NON_WRAPPING_OUTPUT_BUF;
        let (status, consumed, written) = decompress(&mut decompressor, &input, &mut out, 0, flags);
        assert_eq!(status, TINFLStatus::Done);
        assert_eq!(
            consumed,
            stream.len(),
            "must stop exactly at the stream end"
        );
        assert_eq!(written, data.len());
        assert_eq!(out.as_slice(), data.as_slice());
    }

    // ------------------------------------------------------------------
    // structural rejections
    // ------------------------------------------------------------------

    #[test]
    fn decode_rejects_bad_magic_and_versions() {
        let built = build_pack(&[full(3, b"data")]);
        let mut pack = built.finish();
        pack[..4].copy_from_slice(b"XACK");
        assert_eq!(decode(&pack), Err(Error::BadMagic));
        // Restore magic, corrupt the version (trailer now wrong too —
        // the header is checked first, so the version error wins).
        pack[..4].copy_from_slice(&PACK_MAGIC);
        pack[4..8].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(decode(&pack), Err(Error::UnsupportedVersion(1)));
        pack[4..8].copy_from_slice(&3u32.to_be_bytes());
        assert_eq!(decode(&pack), Err(Error::UnsupportedVersion(3)));
    }

    #[test]
    fn decode_refuses_absurd_object_count() {
        // count = 10^9 in a ~40-byte body: must fail on the count
        // bound, before parsing (and before any allocation).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&PACK_MAGIC);
        bytes.extend_from_slice(&PACK_VERSION.to_be_bytes());
        bytes.extend_from_slice(&1_000_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 40]);
        let pack = with_trailer(bytes);
        assert_eq!(decode(&pack), Err(Error::AbsurdObjectCount));
    }

    #[test]
    fn decode_rejects_trailer_mismatch() {
        let built = build_pack(&[full(3, b"payload")]);
        let mut pack = built.finish();
        let last = pack.len() - 1;
        pack[last] ^= 0xff;
        assert_eq!(decode(&pack), Err(Error::TrailerMismatch));
    }

    #[test]
    fn decode_truncated_at_every_boundary() {
        let built = build_pack(&[
            full(1, b"commit body"),
            full(2, b"tree body"),
            full(3, b"blob body"),
        ]);
        let pack = built.finish();
        for cut in 0..pack.len() {
            assert!(
                decode(&pack[..cut]).is_err(),
                "cut at {cut} of {} must fail",
                pack.len()
            );
        }
        // The uncut pack still decodes (sanity for the loop above).
        assert_eq!(decode(&pack).map(|o| o.len()), Ok(3));
    }

    #[test]
    fn decode_rejects_corrupt_zlib() {
        let built = build_pack(&[full(3, b"a rather long payload for a zlib stream")]);
        // Corrupt the last adler32 byte of the only stream *before*
        // sealing the trailer, so the trailer check passes and the
        // zlib checksum is what rejects the pack: the deflate data
        // stays valid, so this deterministically fails adler32.
        let (start, end) = built.streams[0];
        let _ = start;
        let mut built = built;
        built.bytes[end - 1] ^= 0xff;
        let pack = built.finish();
        assert_eq!(decode(&pack), Err(Error::CorruptZlib));
    }

    #[test]
    fn decode_rejects_declared_size_mismatch() {
        let payload = b"five bytes";
        // Declare six bytes while the stream produces five.
        let built = build_pack(&[ObjSpec {
            type_byte: 3,
            payload: payload.to_vec(),
            base: BaseSpec::None,
            declared_size: Some(payload.len() as u64 + 1),
            level: 0,
        }]);
        let pack = built.finish();
        assert_eq!(decode(&pack), Err(Error::CorruptZlib));
    }

    #[test]
    fn decode_rejects_unknown_type() {
        let built = build_pack(&[full(5, b"reserved type")]);
        let pack = built.finish();
        assert_eq!(decode(&pack), Err(Error::UnknownType(5)));
        let built = build_pack(&[full(0, b"invalid type")]);
        let pack = built.finish();
        assert_eq!(decode(&pack), Err(Error::UnknownType(0)));
    }

    #[test]
    fn decode_rejects_trailing_garbage() {
        let built = build_pack(&[full(3, b"body")]);
        let mut body = built.bytes;
        body.push(0xEE); // one stray byte before the trailer
        let pack = with_trailer(body);
        assert_eq!(decode(&pack), Err(Error::TrailingGarbage));
    }

    #[test]
    fn decode_enforces_size_and_total_caps() {
        // Per-object cap below the fixture's size: refused before the
        // stream is even inflated.
        let built = build_pack(&[full(3, b"0123456789")]);
        let pack = built.finish();
        let limits = Limits {
            max_object_size: 9,
            ..Limits::default()
        };
        assert_eq!(
            decode_with_limits(&pack, &limits),
            Err(Error::ObjectTooLarge)
        );

        // Total budget smaller than two objects combined.
        let built = build_pack(&[full(3, b"aaaaaaaaaa"), full(3, b"bbbbbbbbbb")]);
        let pack = built.finish();
        let limits = Limits {
            max_total_output: 15,
            ..Limits::default()
        };
        assert_eq!(
            decode_with_limits(&pack, &limits),
            Err(Error::TotalTooLarge)
        );
        // The same pack under default limits is fine.
        assert_eq!(decode(&pack).map(|o| o.len()), Ok(2));
    }

    // ------------------------------------------------------------------
    // deltas: happy paths
    // ------------------------------------------------------------------

    #[test]
    fn ofs_delta_resolves_against_its_base() {
        let base = b"hello world";
        let mut delta = delta_insert(base.len() as u64, b"hello world!");
        // Also append nothing: delta_insert consumed exactly.
        delta.shrink_to_fit();
        let built = build_pack(&[
            full(3, base),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        let pack = built.finish();
        let objects = decode(&pack).expect("ofs delta decodes");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].data.as_slice(), base.as_slice());
        assert_eq!(objects[1].kind, Kind::Blob, "delta inherits base type");
        assert_eq!(objects[1].data, b"hello world!");
    }

    #[test]
    fn ref_delta_resolves_against_its_base() {
        let base = b"base content for ref delta";
        let built = build_pack(&[
            full(3, base),
            ObjSpec {
                type_byte: 7,
                payload: delta_insert(base.len() as u64, b"ref result"),
                base: BaseSpec::Ref(object_id(Kind::Blob, base)),
                declared_size: None,
                level: 0,
            },
        ]);
        let pack = built.finish();
        let objects = decode(&pack).expect("ref delta decodes");
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[1].kind, Kind::Blob);
        assert_eq!(objects[1].data, b"ref result");
    }

    #[test]
    fn ref_delta_base_is_itself_a_delta() {
        // full → ofs-delta → ref-delta-on-that-delta: exercises the
        // notification cascade (resolve wakes both waiters in order).
        let root = b"AAAA";
        let middle = b"BBBBBBBB";
        let leaf = b"CCCC";
        let built = build_pack(&[
            full(3, root),
            ObjSpec {
                type_byte: 6,
                payload: delta_insert(root.len() as u64, middle),
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
            ObjSpec {
                type_byte: 7,
                payload: delta_insert(middle.len() as u64, leaf),
                base: BaseSpec::Ref(object_id(Kind::Blob, middle)),
                declared_size: None,
                level: 0,
            },
        ]);
        let pack = built.finish();
        let objects = decode(&pack).expect("chained ref delta decodes");
        assert_eq!(objects.len(), 3);
        assert_eq!(objects[2].data.as_slice(), leaf.as_slice());
        assert_eq!(
            objects.iter().map(|o| o.oid()).collect::<Vec<_>>(),
            vec![
                object_id(Kind::Blob, root),
                object_id(Kind::Blob, middle),
                object_id(Kind::Blob, leaf)
            ]
        );
    }

    #[test]
    fn delta_copy_and_insert_chain() {
        // A copy-based delta (base-dependent) stacked two deep.
        let base = b"0123456789";
        let built = build_pack(&[
            full(3, base),
            ObjSpec {
                type_byte: 6,
                payload: delta_copy_all(base.len() as u64),
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
            ObjSpec {
                type_byte: 6,
                payload: delta_copy_all(base.len() as u64),
                base: BaseSpec::Ofs(1),
                declared_size: None,
                level: 0,
            },
        ]);
        let pack = built.finish();
        let objects = decode(&pack).expect("copy chain decodes");
        assert_eq!(objects.len(), 3);
        for o in &objects {
            assert_eq!(o.data.as_slice(), base.as_slice());
        }
    }

    // ------------------------------------------------------------------
    // deltas: adversarial rejections
    // ------------------------------------------------------------------

    #[test]
    fn ofs_offset_beyond_pack_start() {
        // (a) Offset larger than the position: checked_sub fails.
        let built = build_pack(&[ObjSpec {
            type_byte: 6,
            payload: delta_insert(4, b"xxxx"),
            base: BaseSpec::OfsRaw(1_000_000),
            declared_size: None,
            level: 0,
        }]);
        assert_eq!(decode(&built.finish()), Err(Error::OfsOutOfRange));
        // (b) Offset landing before the 12-byte header (single object
        // sits at position 12, so offset 8 → position 4).
        let built = build_pack(&[ObjSpec {
            type_byte: 6,
            payload: delta_insert(4, b"xxxx"),
            base: BaseSpec::OfsRaw(8),
            declared_size: None,
            level: 0,
        }]);
        assert_eq!(decode(&built.finish()), Err(Error::OfsOutOfRange));
        // (c) Self-reference: offset 0 lands on the object itself,
        // which is not a *previous* object start.
        let built = build_pack(&[ObjSpec {
            type_byte: 6,
            payload: delta_insert(4, b"xxxx"),
            base: BaseSpec::OfsRaw(0),
            declared_size: None,
            level: 0,
        }]);
        assert_eq!(decode(&built.finish()), Err(Error::OfsOutOfRange));
    }

    #[test]
    fn ofs_offset_into_object_interior() {
        // Base position lands one byte into object 0 — inside it, not
        // at its type byte.
        let built = build_pack(&[
            full(3, b"an object long enough to land inside"),
            ObjSpec {
                type_byte: 6,
                payload: delta_insert(10, b"0123456789"),
                base: BaseSpec::OfsInto { idx: 0, skip: 1 },
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::OfsOutOfRange));
    }

    #[test]
    fn thin_pack_ref_base_missing_is_refused() {
        // One full object + one REF_DELTA whose base id names nothing
        // in this pack (v1 refuses thin packs).
        let built = build_pack(&[
            full(3, b"present"),
            ObjSpec {
                type_byte: 7,
                payload: delta_insert(100, b"leaf"),
                base: BaseSpec::Ref([0x5A; 20]),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::ThinPack));
    }

    #[test]
    fn delta_loop_of_two_ref_objects_is_refused() {
        // A hand-built 2-object loop: A declares B's id as its base,
        // B declares A's. Both deltas insert-only, so the fixture is
        // constructible; neither id is resolvable, the fixpoint
        // stalls, and the size-consistency classification sees every
        // REF leftover has a partner → DeltaCycle (never a hang).
        let content_a = b"AAAA";
        let content_b = b"BBBBB";
        let oid_a = object_id(Kind::Blob, content_a);
        let oid_b = object_id(Kind::Blob, content_b);
        let built = build_pack(&[
            ObjSpec {
                type_byte: 7,
                payload: delta_insert(content_b.len() as u64, content_a),
                base: BaseSpec::Ref(oid_b),
                declared_size: None,
                level: 0,
            },
            ObjSpec {
                type_byte: 7,
                payload: delta_insert(content_a.len() as u64, content_b),
                base: BaseSpec::Ref(oid_a),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaCycle));
    }

    #[test]
    fn delta_chain_depth_over_cap_is_refused() {
        // full → d1 → d2 → d3 → d4 with a cap of 3: the fourth link
        // exceeds it.
        let base = b"x";
        let mut objs = vec![full(3, base)];
        for _ in 0..4 {
            objs.push(ObjSpec {
                type_byte: 6,
                payload: delta_copy_all(base.len() as u64),
                base: BaseSpec::Ofs(objs.len() - 1),
                declared_size: None,
                level: 0,
            });
        }
        let pack = build_pack(&objs).finish();
        let limits = Limits {
            max_delta_chain: 3,
            ..Limits::default()
        };
        assert_eq!(
            decode_with_limits(&pack, &limits),
            Err(Error::DeltaChainTooDeep)
        );
        // The same pack under the default cap (50) decodes.
        assert_eq!(decode(&pack).map(|o| o.len()), Ok(5));
    }

    #[test]
    fn delta_copy_out_of_base_bounds_is_refused() {
        // Copy instruction claiming 8 bytes from a 4-byte base.
        let mut delta = Vec::new();
        put_varint(&mut delta, 4); // declared base size (matches)
        put_varint(&mut delta, 8); // result size 8
        delta.push(0x90); // copy: one size byte, no offset bytes
        delta.push(8); // size 8 > base len 4
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_insert_over_result_size_is_refused() {
        // Result declared 4 bytes, insert instruction offers 5.
        let mut delta = Vec::new();
        put_varint(&mut delta, 4); // base size
        put_varint(&mut delta, 4); // result size
        delta.push(5); // insert 5
        delta.extend_from_slice(b"12345");
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_result_over_cap_is_refused() {
        // Result size 11 > the 10-byte cap; refused at parse time,
        // before any result buffer exists.
        let mut delta = Vec::new();
        put_varint(&mut delta, 2); // base size
        put_varint(&mut delta, 11); // result size over cap
        delta.push(5);
        delta.extend_from_slice(b"12345");
        let built = build_pack(&[
            full(3, b"hi"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        let pack = built.finish();
        let limits = Limits {
            max_object_size: 10,
            ..Limits::default()
        };
        assert_eq!(
            decode_with_limits(&pack, &limits),
            Err(Error::ObjectTooLarge)
        );
    }

    #[test]
    fn delta_base_size_mismatch_is_refused() {
        // Declared base size 999 vs a real 4-byte base.
        let mut delta = Vec::new();
        put_varint(&mut delta, 999);
        put_varint(&mut delta, 4);
        delta.push(4);
        delta.extend_from_slice(b"1234");
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_result_not_fully_produced_is_refused() {
        // Result declared 8, instructions only write 4.
        let mut delta = Vec::new();
        put_varint(&mut delta, 4);
        put_varint(&mut delta, 8);
        delta.push(4);
        delta.extend_from_slice(b"1234");
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_trailing_bytes_are_refused() {
        // Result produced in full, then one stray instruction byte.
        let mut delta = Vec::new();
        put_varint(&mut delta, 4);
        put_varint(&mut delta, 4);
        delta.push(4);
        delta.extend_from_slice(b"1234");
        delta.push(4); // never read: result already complete
        delta.extend_from_slice(b"5678");
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_reserved_instruction_is_refused() {
        let mut delta = Vec::new();
        put_varint(&mut delta, 4);
        put_varint(&mut delta, 4);
        delta.push(0x00); // reserved opcode
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_omitted_copy_size_means_64k_and_is_bounds_checked() {
        // Copy with no size bytes → 0x10000 bytes from a 4-byte base.
        let mut delta = Vec::new();
        put_varint(&mut delta, 4);
        put_varint(&mut delta, 4);
        delta.push(0x80); // copy, no offset, no size bytes
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::DeltaMalformed));
    }

    #[test]
    fn delta_varint_overflow_is_refused() {
        // Base-size varint with more continuation bytes than 64 bits.
        let mut delta = vec![0xff; 12];
        delta.push(0x01);
        let built = build_pack(&[
            full(3, b"1234"),
            ObjSpec {
                type_byte: 6,
                payload: delta,
                base: BaseSpec::Ofs(0),
                declared_size: None,
                level: 0,
            },
        ]);
        assert_eq!(decode(&built.finish()), Err(Error::SizeOverflow));
    }
}
