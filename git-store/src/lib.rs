//! git **local object store** formats — milestone G4/G5 of
//! docs/git-ssh-deps.md §A.4: loose objects (encode + decode), tree
//! serialization, commit objects, the v2 index and refs/HEAD.
//!
//! The fetch side (`git-pack`) already owns *decoding* a pack into
//! in-memory objects and the hostile-input parsers for tree/commit
//! payloads. This crate is the **writing** half — the bytes a real
//! `git` must be able to read back — plus the small decode side needed
//! by `log`/`status`-lite and by the kernel's own read-back proof. It is
//! `#![no_std]`, uses only the two crates reviewed in G3a (`sha1`,
//! `miniz_oxide`), and `#![forbid(unsafe_code)]`, so the kernel's
//! ring-0 build cannot smuggle in an unchecked cast through it.
//!
//! Formats, each documented next to its module and cited to git's own
//! implementation:
//!
//! - [`object`] — `<type> <size>\0<content>` → SHA-1 → zlib deflate →
//!   `objects/xx/y…` (git's loose-object format, `gitformat-objects`).
//! - [`tree`] — entries `<mode> SP <name> NUL <20-byte oid>`, sorted by
//!   git's `base_name_compare` (the `foo` / `foo.txt` / `foo/bar`
//!   ordering trap lives here).
//! - [`commit`] — `tree`/`parent`/`author`/`committer`/blank/message,
//!   byte-exact to `git commit-tree`.
//! - [`index`] — the binary `DIRC` v2 index (`cache.h`'s
//!   `cache_entry` layout + 8-byte entry padding), with its SHA-1
//!   trailer.
//! - [`refs`] — `HEAD` (`ref: refs/heads/<branch>`) and a 40-hex ref
//!   file.
//! - [`layout`] — assemble a directory hierarchy of paths into nested
//!   tree objects, emitting every tree bottom-up.
//!
//! Every parser refuses hostile input: truncated zlib streams, bad
//! headers, size mismatches, oversized objects, unknown modes, empty
//! or `/`-bearing names, unsorted or duplicate index entries, bad
//! checksums, short refs and impossible symbolic refs. No `unwrap`,
//! no panics and no indexing on caller-controlled offsets; arithmetic
//! is checked. The adversarial suite is `tests/hostile.rs`.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

mod commit;
mod index;
mod layout;
mod object;
mod refs;
mod tree;

pub use commit::{MAX_PARENTS, Signature, encode_commit};
pub use index::{
    Index, IndexEntry, IndexRecord, MAX_INDEX_ENTRIES, MAX_INDEX_PATH, encode_index, parse_index,
};
pub use layout::{
    BuiltTrees, MAX_PATH, MAX_TREE_DEPTH, MAX_TREE_DIRS, PathEntry, build_tree_hierarchy,
};
pub use object::{
    Kind, LOOSE_PATH_LEN, LooseObject, MAX_COMPRESSED_SIZE, MAX_OBJECT_SIZE, Object, decode_loose,
    decode_loose_with_limit, encode_loose, encode_loose_with_limit, encode_preimage,
    encode_preimage_with_limit, hex_oid, loose_path, object_oid, parse_oid,
};
pub use refs::{encode_head, encode_ref, parse_head, parse_ref, valid_ref_name};
pub use tree::{MAX_NAME_LEN, MAX_TREE_ENTRIES, Mode, TreeEntry, base_name_compare, encode_tree};

/// Why an object, tree, commit, index or ref was refused. Fail-closed:
/// a caller must discard the whole thing — no partial writes, no
/// "best-effort" prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Object content exceeds [`MAX_OBJECT_SIZE`] (or the caller's
    /// tighter limit); the kernel's own pack limits are stricter.
    ObjectTooLarge,
    /// A compressed loose object would exceed
    /// [`MAX_COMPRESSED_SIZE`].
    CompressedTooLarge,
    /// The loose header is not `<type> SP <decimal-size> NUL`.
    BadHeader,
    /// The header names a type other than commit/tree/blob/tag.
    UnknownType,
    /// The header's declared size does not equal the remaining bytes.
    SizeMismatch,
    /// The zlib stream is corrupt, truncated, fails adler32, or expands
    /// past the caller's bound.
    CorruptZlib,
    /// The compressed input is empty or longer than
    /// [`MAX_COMPRESSED_SIZE`].
    InputTooLarge,
    /// A mode is not one of git's five tree modes.
    BadMode,
    /// A name/path is empty, `.`/`..`, contains `/` (where a component
    /// is required) or a NUL, or is otherwise invalid.
    BadName,
    /// Two entries in one tree (or index) share a name.
    DuplicateEntry,
    /// More entries than the structure's cap.
    TooManyEntries,
    /// The path hierarchy nests deeper than the layout cap.
    TooDeep,
    /// A path or ref is longer than the format's cap.
    PathTooLong,
    /// The index signature is not `DIRC`.
    BadIndexSignature,
    /// The index version is not 2.
    UnsupportedIndexVersion(u32),
    /// The index's trailing SHA-1 does not match its contents.
    ChecksumMismatch,
    /// Index entries are not in strictly ascending path order.
    UnsortedIndex,
    /// An index entry asks for an extended (long) name, which this
    /// writer does not produce.
    ExtendedFlags,
    /// The index is structurally malformed (short entry, bad padding,
    /// garbage before the trailer, absurd count).
    BadIndex,
    /// A ref or HEAD payload violates git's ref-name grammar (the
    /// documented subset in [`refs`]).
    BadRef,
    /// A ref does not name a 40-hex lowercase object id.
    BadOid,
    /// A commit identity has an invalid name/email/epoch.
    BadIdent,
    /// A commit message contains a NUL (git's message is text; NUL is
    /// not representable in the porcelain round trip).
    BadMessage,
    /// More parents than [`MAX_PARENTS`].
    TooManyParents,
}
