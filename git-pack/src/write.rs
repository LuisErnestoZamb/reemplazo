//! Packfile v2 **encoding** — the `git push` half of the git milestones
//! (docs/git-ssh-deps.md §A.4 row G6, landed here as milestone **G5**:
//! "pack writer + receive-pack client, proven against a mock server").
//!
//! # Why no deltas (the documented policy of §A.3 item 4)
//!
//! A pack of **full (non-delta) objects** is legal and is accepted by
//! `git receive-pack`: deltas are an encoding optimization, not part of
//! the protocol contract. Delta *encoding* (window search, thin packs,
//! `OFS_DELTA` bases) is explicitly deferred — it belongs after the
//! smoke chain has a real server to measure against. What this module
//! writes is therefore the simplest conforming pack:
//!
//! ```text
//! "PACK" | version (2) u32 BE | object count u32 BE
//! per object:  type+size varint header, then zlib(deflate(content))
//! trailer: SHA-1 over every byte before it
//! ```
//!
//! # Two entry points, one writer
//!
//! - [`encode`] / [`encode_with_limits`] — the slice API: every object is
//!   already in memory, the output is a `Vec<u8>`. Host tests and any
//!   future bulk caller use this. It sorts by object id, so the same
//!   object set always produces byte-identical output (fixtures stay
//!   stable) and independent of caller order.
//! - [`PackWriter`] — the streaming API: the header is written once, then
//!   [`PackWriter::object`] appends one object at a time. The kernel's
//!   push uses it to append a pack **after** the receive-pack command
//!   pkt-lines in one buffer, reading one loose object at a time from
//!   disk — peak heap is the pack plus a single object, never the whole
//!   repository re-encoded.
//!
//! # Bounds
//!
//! [`EncodeLimits`] caps object count, one object's content and the pack
//! size; every cap is checked **before** the corresponding bytes are
//! appended, and all arithmetic is checked. A failed write leaves `out`
//! in an unspecified partial state — the caller discards it (fail-closed;
//! nothing is silently "best effort").
//!
//! No hand-rolled hashing or compression: object ids and the pack trailer
//! come from `sha1` 0.11, deflate from `miniz_oxide` 0.9 — the two crates
//! reviewed for the decoder (docs/git-ssh-deps.md §A.1). Compression
//! level 1 (`Z_BEST_SPEED`) mirrors git's `pack.compression` default on
//! the 5400 rpm target: the ratio difference at level 6 is noise next to
//! PIO/upload latency.

use crate::{Kind, PACK_MAGIC, PACK_VERSION, object_id};
use alloc::vec::Vec;
use miniz_oxide::deflate::compress_to_vec_zlib;
use sha1::{Digest, Sha1};

/// zlib level for pack entries (`Z_BEST_SPEED`; see the module docs).
const PACK_ZLIB_LEVEL: u8 = 1;

/// Default object-count cap (the decoder's own kernel-side cap is 10 000).
pub const DEFAULT_MAX_OBJECTS: u32 = 100_000;
/// Default per-object content cap (same ceiling as the decoder's default).
pub const DEFAULT_MAX_OBJECT_SIZE: usize = 16 * 1024 * 1024;
/// Default pack-size cap (the decoder's default total-output ceiling).
pub const DEFAULT_MAX_PACK_BYTES: usize = 256 * 1024 * 1024;

/// Why an encode was refused. Fail-closed: an error means the pack is
/// not usable — never a partially valid stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// [`encode`] was given a non-empty `out` buffer (it must own the
    /// whole vector so the trailer hashes exactly the pack).
    NotEmpty,
    /// The declared object count (or the slice length) exceeds
    /// [`EncodeLimits::max_objects`].
    TooManyObjects,
    /// An object's content exceeds [`EncodeLimits::max_object_size`].
    ObjectTooLarge,
    /// The pack would exceed [`EncodeLimits::max_pack_bytes`].
    PackTooLarge,
    /// [`PackWriter::object`] was called more times than the count the
    /// header declared.
    CountExceeded,
    /// [`PackWriter::finish`] was reached with fewer objects than the
    /// header declared.
    CountMismatch,
    /// The object id supplied for an object is not the id of its content
    /// (a caller bug; refusing it keeps the pack self-consistent).
    OidMismatch,
    /// The same object id appears twice in one [`encode`] call.
    DuplicateObject,
    /// A length does not fit the format's 64-bit size field.
    SizeOverflow,
}

/// Caps applied by [`PackWriter`]. Mirrors the decoder's [`crate::Limits`]
/// where the two overlap (per-object size, pack size).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodeLimits {
    /// Maximum number of objects the pack may declare.
    pub max_objects: u32,
    /// Maximum content bytes of one object.
    pub max_object_size: usize,
    /// Maximum pack bytes, header and trailer included.
    pub max_pack_bytes: usize,
}

impl Default for EncodeLimits {
    fn default() -> EncodeLimits {
        EncodeLimits {
            max_objects: DEFAULT_MAX_OBJECTS,
            max_object_size: DEFAULT_MAX_OBJECT_SIZE,
            max_pack_bytes: DEFAULT_MAX_PACK_BYTES,
        }
    }
}

/// Streaming pack writer: header first, then one [`Kind`] + content per
/// call, then [`PackWriter::finish`] appends the SHA-1 trailer.
///
/// The pack is appended to `out` at the length it had when
/// [`PackWriter::new`] was called; the trailer hashes only the appended
/// bytes. That is what lets the kernel prepend the receive-pack command
/// pkt-lines to the same buffer.
pub struct PackWriter<'a> {
    out: &'a mut Vec<u8>,
    /// First byte of the pack inside `out`.
    base: usize,
    limits: EncodeLimits,
    /// Object count written in the header.
    declared: u32,
    /// Objects written so far.
    written: u32,
}

impl<'a> PackWriter<'a> {
    /// Start a pack with `count` objects appended to `out`.
    ///
    /// # Errors
    /// [`EncodeError::TooManyObjects`] when `count` exceeds the cap,
    /// [`EncodeError::PackTooLarge`] when the fixed header + trailer
    /// alone cannot fit.
    pub fn new(
        out: &'a mut Vec<u8>,
        count: u32,
        limits: EncodeLimits,
    ) -> Result<PackWriter<'a>, EncodeError> {
        if count > limits.max_objects {
            return Err(EncodeError::TooManyObjects);
        }
        let fixed = 12usize.checked_add(20).ok_or(EncodeError::PackTooLarge)?;
        if fixed > limits.max_pack_bytes {
            return Err(EncodeError::PackTooLarge);
        }
        let base = out.len();
        out.extend_from_slice(&PACK_MAGIC);
        out.extend_from_slice(&PACK_VERSION.to_be_bytes());
        out.extend_from_slice(&count.to_be_bytes());
        Ok(PackWriter {
            out,
            base,
            limits,
            declared: count,
            written: 0,
        })
    }

    /// Append one full (non-delta) object; returns its git object id.
    ///
    /// # Errors
    /// [`EncodeError::CountExceeded`] past the declared count,
    /// [`EncodeError::ObjectTooLarge`], [`EncodeError::PackTooLarge`],
    /// [`EncodeError::SizeOverflow`].
    pub fn object(&mut self, kind: Kind, data: &[u8]) -> Result<[u8; 20], EncodeError> {
        if self.written >= self.declared {
            return Err(EncodeError::CountExceeded);
        }
        if data.len() > self.limits.max_object_size {
            return Err(EncodeError::ObjectTooLarge);
        }
        let size = u64::try_from(data.len()).map_err(|_| EncodeError::SizeOverflow)?;
        let header = header_len(size);
        let compressed = compress_to_vec_zlib(data, PACK_ZLIB_LEVEL);
        // Check the bound before appending anything (see module docs).
        let added = header
            .checked_add(compressed.len())
            .ok_or(EncodeError::PackTooLarge)?;
        let pack_len = self
            .out
            .len()
            .checked_sub(self.base)
            .ok_or(EncodeError::PackTooLarge)?
            .checked_add(added)
            .ok_or(EncodeError::PackTooLarge)?;
        if pack_len > self.limits.max_pack_bytes {
            return Err(EncodeError::PackTooLarge);
        }
        push_header(self.out, kind.type_byte(), size);
        self.out.extend_from_slice(&compressed);
        self.written = self.written.saturating_add(1);
        Ok(object_id(kind, data))
    }

    /// Objects written so far (for progress/reporting).
    pub fn written(&self) -> u32 {
        self.written
    }

    /// Append the SHA-1 trailer; returns the pack length (header +
    /// objects + trailer), excluding any prefix the caller had in `out`.
    ///
    /// # Errors
    /// [`EncodeError::CountMismatch`] when fewer objects were written
    /// than the header declared, [`EncodeError::PackTooLarge`] when the
    /// trailer pushes the pack over its cap.
    pub fn finish(self) -> Result<usize, EncodeError> {
        if self.written != self.declared {
            return Err(EncodeError::CountMismatch);
        }
        let len = self
            .out
            .len()
            .checked_sub(self.base)
            .ok_or(EncodeError::PackTooLarge)?;
        let total = len.checked_add(20).ok_or(EncodeError::PackTooLarge)?;
        if total > self.limits.max_pack_bytes {
            return Err(EncodeError::PackTooLarge);
        }
        // Hash exactly the pack bytes (the prefix is not ours).
        let body = self.out.get(self.base..).ok_or(EncodeError::PackTooLarge)?;
        let digest = Sha1::digest(body);
        self.out.extend_from_slice(digest.as_slice());
        Ok(self.out.len() - self.base)
    }
}

/// Encode `objects` as a v2 pack of full objects with the default
/// [`EncodeLimits`]. Order is normalized: entries are written in
/// ascending object-id order, so the same set always yields the same
/// bytes. Each supplied id must equal `SHA-1("<type> <len>\0<content>")`
/// (checked; a mismatch is a caller bug, refused as
/// [`EncodeError::OidMismatch`]).
///
/// `out` must be empty; on success it holds exactly the pack. On error
/// its state is unspecified — discard it.
pub fn encode(
    objects: &[([u8; 20], Kind, &[u8])],
    out: &mut Vec<u8>,
) -> Result<usize, EncodeError> {
    encode_with_limits(objects, out, EncodeLimits::default())
}

/// [`encode`] under caller-supplied caps — the kernel's push uses a
/// 2 MiB pack / 4 MiB object limit.
pub fn encode_with_limits(
    objects: &[([u8; 20], Kind, &[u8])],
    out: &mut Vec<u8>,
    limits: EncodeLimits,
) -> Result<usize, EncodeError> {
    if !out.is_empty() {
        return Err(EncodeError::NotEmpty);
    }
    let count = u32::try_from(objects.len()).map_err(|_| EncodeError::TooManyObjects)?;
    if count > limits.max_objects {
        return Err(EncodeError::TooManyObjects);
    }
    // Deterministic order: ascending object id (the `.idx` order too).
    let mut order: Vec<usize> = (0..objects.len()).collect();
    order.sort_unstable_by(|&a, &b| {
        let (Some(oa), Some(ob)) = (objects.get(a), objects.get(b)) else {
            return core::cmp::Ordering::Equal;
        };
        oa.0.cmp(&ob.0)
    });
    for pair in order.windows(2) {
        let (Some(a), Some(b)) = (
            pair.first().and_then(|&i| objects.get(i)),
            pair.get(1).and_then(|&i| objects.get(i)),
        ) else {
            continue;
        };
        if a.0 == b.0 {
            return Err(EncodeError::DuplicateObject);
        }
    }
    let mut writer = PackWriter::new(out, count, limits)?;
    for index in order {
        let Some(&(oid, kind, data)) = objects.get(index) else {
            return Err(EncodeError::OidMismatch);
        };
        if writer.object(kind, data)? != oid {
            return Err(EncodeError::OidMismatch);
        }
    }
    writer.finish()
}

/// Number of bytes the type+size varint occupies for `size` (the inverse
/// of the decoder's header parse: 4 size bits in the first byte, 7 per
/// continuation).
fn header_len(size: u64) -> usize {
    let mut len = 1usize;
    let mut rest = size >> 4;
    while rest != 0 {
        len += 1;
        rest >>= 7;
    }
    len
}

/// Write `type_byte` + `size` as the pack's object header varint.
fn push_header(out: &mut Vec<u8>, type_byte: u8, size: u64) {
    let mut byte = ((type_byte & 0x07) << 4) | (size & 0x0f) as u8;
    let mut rest = size >> 4;
    while rest != 0 {
        out.push(byte | 0x80);
        byte = (rest & 0x7f) as u8;
        rest >>= 7;
    }
    out.push(byte);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HeaderStep, decode, decode_with_index, parse_header};
    use std::vec;

    fn oid_of(kind: Kind, data: &[u8]) -> [u8; 20] {
        object_id(kind, data)
    }

    fn one(kind: Kind, data: &[u8]) -> Vec<([u8; 20], Kind, &[u8])> {
        vec![(oid_of(kind, data), kind, data)]
    }

    #[test]
    fn roundtrips_one_blob_byte_exact() {
        let data = b"hello pack encoder\n";
        let mut pack = Vec::new();
        let len = encode(&one(Kind::Blob, data), &mut pack).expect("encodes");
        assert_eq!(len, pack.len());
        let objects = decode(&pack).expect("decodes");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].kind, Kind::Blob);
        assert_eq!(objects[0].data, data);
        assert_eq!(objects[0].oid(), oid_of(Kind::Blob, data));
    }

    #[test]
    fn roundtrips_all_four_kinds() {
        let commit = b"tree 0123456789abcdef0123456789abcdef01234567\n\nmsg\n";
        let tree = b"100644 a\0aaaaaaaaaaaaaaaaaaaa";
        let blob = b"\x00\x01\x02 binary \xff";
        let tag = b"object deadbeef\ntype commit\ntag v1\n";
        let objects = vec![
            (
                oid_of(Kind::Commit, commit),
                Kind::Commit,
                commit.as_slice(),
            ),
            (oid_of(Kind::Tree, tree), Kind::Tree, tree.as_slice()),
            (oid_of(Kind::Blob, blob), Kind::Blob, blob.as_slice()),
            (oid_of(Kind::Tag, tag), Kind::Tag, tag.as_slice()),
        ];
        let mut pack = Vec::new();
        encode(&objects, &mut pack).expect("encodes");
        let decoded = decode(&pack).expect("decodes");
        assert_eq!(decoded.len(), 4);
        // Writer order is oid-sorted; match by content, not index.
        for &(oid, kind, data) in &objects {
            let found = decoded
                .iter()
                .find(|object| object.oid() == oid)
                .expect("object present");
            assert_eq!(found.kind, kind);
            assert_eq!(found.data, data);
        }
    }

    #[test]
    fn header_is_exact_pack_v2() {
        let mut pack = Vec::new();
        encode(&one(Kind::Blob, b"x"), &mut pack).expect("encodes");
        assert_eq!(&pack[..4], b"PACK");
        assert_eq!(&pack[4..8], &2u32.to_be_bytes());
        assert_eq!(&pack[8..12], &1u32.to_be_bytes());
        assert_eq!(parse_header(&pack), HeaderStep::Done { count: 1 });
    }

    #[test]
    fn trailer_is_sha1_of_everything_before_it() {
        let mut pack = Vec::new();
        encode(&one(Kind::Blob, b"trailer check"), &mut pack).expect("encodes");
        let (body, trailer) = pack.split_at(pack.len() - 20);
        assert_eq!(Sha1::digest(body).as_slice(), trailer);
        // A flipped trailer byte is refused by the decoder.
        let mut corrupt = pack.clone();
        corrupt[pack.len() - 1] ^= 0x01;
        assert!(decode(&corrupt).is_err());
    }

    #[test]
    fn empty_object_set_is_a_valid_empty_pack() {
        let mut pack = Vec::new();
        let len = encode(&[], &mut pack).expect("encodes");
        assert_eq!(len, 32); // 12 header + 20 trailer
        assert_eq!(decode(&pack).expect("decodes").len(), 0);
    }

    #[test]
    fn zero_length_object_roundtrips() {
        let mut pack = Vec::new();
        encode(&one(Kind::Blob, b""), &mut pack).expect("encodes");
        let objects = decode(&pack).expect("decodes");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].data.len(), 0);
        // The canonical empty blob id.
        assert_eq!(objects[0].oid(), oid_of(Kind::Blob, b""),);
    }

    #[test]
    fn object_order_is_oid_sorted_and_input_order_independent() {
        let a = b"aaa".as_slice();
        let b = b"bbb".as_slice();
        let c = b"ccc".as_slice();
        let mut first = vec![
            (oid_of(Kind::Blob, a), Kind::Blob, a),
            (oid_of(Kind::Blob, b), Kind::Blob, b),
            (oid_of(Kind::Blob, c), Kind::Blob, c),
        ];
        let mut pack_a = Vec::new();
        encode(&first, &mut pack_a).expect("encodes");
        first.reverse();
        let mut pack_b = Vec::new();
        encode(&first, &mut pack_b).expect("encodes");
        assert_eq!(pack_a, pack_b, "oid sort must make the pack deterministic");
        let objects = decode(&pack_a).expect("decodes");
        let mut oids: Vec<[u8; 20]> = objects.iter().map(|o| o.oid()).collect();
        let mut sorted = oids.clone();
        sorted.sort_unstable();
        assert_eq!(oids, sorted);
        oids.clear();
    }

    #[test]
    fn large_object_roundtrips_and_compresses() {
        // 256 KiB of a repeating pattern: bounded, but past every
        // one-byte size varint boundary.
        let data: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
        let mut pack = Vec::new();
        encode(&one(Kind::Blob, &data), &mut pack).expect("encodes");
        assert!(pack.len() < data.len(), "the pattern must compress");
        let objects = decode(&pack).expect("decodes");
        assert_eq!(objects.len(), 1);
        assert_eq!(objects[0].data, data);
    }

    #[test]
    fn size_varint_boundaries_roundtrip() {
        for size in [0usize, 1, 14, 15, 16, 17, 2047, 2048, 2049, 65_535, 65_536] {
            let data = vec![0x5au8; size];
            let mut pack = Vec::new();
            encode(&one(Kind::Blob, &data), &mut pack).expect("encodes");
            let objects = decode(&pack).expect("decodes");
            assert_eq!(objects[0].data.len(), size, "size {size}");
        }
    }

    #[test]
    fn encode_then_decode_with_index_agrees() {
        let a = b"alpha".as_slice();
        let b = b"beta".as_slice();
        let objects = vec![
            (oid_of(Kind::Blob, a), Kind::Blob, a),
            (oid_of(Kind::Blob, b), Kind::Blob, b),
        ];
        let mut pack = Vec::new();
        encode(&objects, &mut pack).expect("encodes");
        let (decoded, index) = decode_with_index(&pack).expect("decodes");
        assert_eq!(decoded.len(), 2);
        assert_eq!(index.len(), 2);
        for object in &decoded {
            let offset = index.get(&object.oid()).expect("indexed");
            assert!(offset >= 12 && (offset as usize) < pack.len() - 20);
        }
    }

    #[test]
    fn writer_prefix_is_not_part_of_the_pack() {
        // The kernel appends the pack after command pkt-lines; the
        // trailer must cover the pack only, and the prefix must survive.
        let prefix = b"0044c0ffee refs/heads/main\0report-status\n0000";
        let mut out = Vec::from(&prefix[..]);
        let mut writer = PackWriter::new(&mut out, 1, EncodeLimits::default()).expect("starts");
        writer
            .object(Kind::Blob, b"prefixed")
            .expect("writes object");
        let len = writer.finish().expect("finishes");
        assert_eq!(&out[..prefix.len()], prefix);
        let pack = &out[prefix.len()..];
        assert_eq!(pack.len(), len);
        assert_eq!(decode(pack).expect("decodes").len(), 1);
    }

    #[test]
    fn writer_refuses_more_objects_than_declared() {
        let mut out = Vec::new();
        let mut writer = PackWriter::new(&mut out, 1, EncodeLimits::default()).expect("starts");
        writer.object(Kind::Blob, b"a").expect("first fits");
        assert_eq!(
            writer.object(Kind::Blob, b"b"),
            Err(EncodeError::CountExceeded)
        );
    }

    #[test]
    fn writer_refuses_to_finish_short() {
        let mut out = Vec::new();
        let writer = PackWriter::new(&mut out, 3, EncodeLimits::default()).expect("starts");
        assert_eq!(writer.finish(), Err(EncodeError::CountMismatch));
    }

    #[test]
    fn object_count_cap_is_enforced() {
        let limits = EncodeLimits {
            max_objects: 2,
            ..EncodeLimits::default()
        };
        let mut out = Vec::new();
        assert_eq!(
            PackWriter::new(&mut out, 3, limits).err(),
            Some(EncodeError::TooManyObjects)
        );
        let a = b"a".as_slice();
        let b = b"b".as_slice();
        let c = b"c".as_slice();
        let objects = vec![
            (oid_of(Kind::Blob, a), Kind::Blob, a),
            (oid_of(Kind::Blob, b), Kind::Blob, b),
            (oid_of(Kind::Blob, c), Kind::Blob, c),
        ];
        let mut pack = Vec::new();
        assert_eq!(
            encode_with_limits(&objects, &mut pack, limits),
            Err(EncodeError::TooManyObjects)
        );
    }

    #[test]
    fn object_size_cap_is_enforced() {
        let limits = EncodeLimits {
            max_object_size: 8,
            ..EncodeLimits::default()
        };
        let data = b"0123456789".as_slice();
        let objects = one(Kind::Blob, data);
        let mut pack = Vec::new();
        assert_eq!(
            encode_with_limits(&objects, &mut pack, limits),
            Err(EncodeError::ObjectTooLarge)
        );
    }

    #[test]
    fn pack_size_cap_is_enforced() {
        let data = b"incompressible-ish payload".as_slice();
        let objects = one(Kind::Blob, data);
        let mut pack = Vec::new();
        // 40 bytes cannot hold 12 header + object + 20 trailer.
        let limits = EncodeLimits {
            max_pack_bytes: 40,
            ..EncodeLimits::default()
        };
        assert_eq!(
            encode_with_limits(&objects, &mut pack, limits),
            Err(EncodeError::PackTooLarge)
        );
    }

    #[test]
    fn oid_mismatch_is_refused() {
        let data = b"the real content".as_slice();
        let mut wrong = oid_of(Kind::Blob, data);
        wrong[0] ^= 0xff;
        let mut pack = Vec::new();
        assert_eq!(
            encode(&[(wrong, Kind::Blob, data)], &mut pack),
            Err(EncodeError::OidMismatch)
        );
    }

    #[test]
    fn duplicate_oids_are_refused() {
        let data = b"twice".as_slice();
        let oid = oid_of(Kind::Blob, data);
        let mut pack = Vec::new();
        assert_eq!(
            encode(
                &[(oid, Kind::Blob, data), (oid, Kind::Blob, data)],
                &mut pack
            ),
            Err(EncodeError::DuplicateObject)
        );
    }

    #[test]
    fn encode_requires_an_empty_vector() {
        let mut pack = Vec::from(&b"prefix"[..]);
        assert_eq!(
            encode(&one(Kind::Blob, b"x"), &mut pack),
            Err(EncodeError::NotEmpty)
        );
    }

    #[test]
    fn corrupted_encoder_output_is_refused_by_the_decoder() {
        // Writer/decoder agreement check: flipping a content byte must
        // fail the trailer (the decoder verifies it before objects).
        let mut pack = Vec::new();
        encode(&one(Kind::Blob, b"integrity"), &mut pack).expect("encodes");
        let at = 12; // first object header byte
        if let Some(byte) = pack.get_mut(at) {
            *byte ^= 0x01;
        }
        assert!(decode(&pack).is_err());
    }

    #[test]
    fn header_len_matches_the_written_varint() {
        for size in [0u64, 15, 16, 2047, 2048, 1 << 40] {
            let mut out = Vec::new();
            push_header(&mut out, 3, size);
            assert_eq!(out.len(), header_len(size), "size {size}");
        }
    }
}
