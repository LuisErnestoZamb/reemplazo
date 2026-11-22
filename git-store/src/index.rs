//! The git **index** (`.git/index`), version 2 — the binary cache that
//! makes `git status`/`git commit` work without re-reading every file.
//!
//! Layout (git's `Documentation/gitformat-index`, and `cache.h`'s
//! `struct cache_entry`):
//!
//! ```text
//! header   = "DIRC" <version:u32 BE> <entry-count:u32 BE>
//! entry    = ctime:u32 ctime-ns:u32 mtime:u32 mtime-ns:u32
//!            dev:u32 ino:u32 mode:u32 uid:u32 gid:u32 size:u32
//!            oid:20  flags:u16  path  NUL-padding
//! trailer  = SHA-1(everything before it):20
//! ```
//!
//! The fixed part before the path is 62 bytes (`cache_entry_size`'s
//! `offsetof(struct cache_entry, name)`), and the entry's total size is
//! `(62 + name-len + 8) & ~7` — i.e. the name plus its NUL plus zero
//! padding, rounded up to a multiple of 8. (The `+ 8` is git's own
//! expression in `cache.h`; a 1-byte name yields 64, a 2-byte name 72.)
//!
//! # Our filesystem has no inode semantics
//!
//! The FAT16 volume has no inode numbers, device ids or owners, so this
//! writer uses documented placeholders: `dev = ino = uid = gid = 0`,
//! `ctime = mtime`, nanoseconds `0`, and the real `mode`/`size`/`mtime`
//! the caller supplies (mode from the fetched tree, size/mtime from the
//! checkout). Git reads such an index without complaint — those fields
//! only drive stat-based "unchanged?" shortcuts, which simply miss and
//! fall back to content comparison.
//!
//! Entry names are sorted byte-wise by git (not by
//! `base_name_compare`), the flags field carries the name length in its
//! low 12 bits (stage 0, no extended entries), and there are no
//! extension sections — this crate writes and accepts exactly that
//! shape.

use crate::Error;
use crate::tree::Mode;
use alloc::vec::Vec;
use sha1::{Digest, Sha1};

/// Cap on entries parsed or written (64 Ki). The index's own count is
/// u32; this cap is what bounds the allocation this crate performs.
pub const MAX_INDEX_ENTRIES: usize = 65_536;
/// Longest path accepted: the v2 flags field stores the length in 12
/// bits, and this writer does not emit extended entries, so 0xFFF is
/// the representable maximum.
pub const MAX_INDEX_PATH: usize = 0xFFF;

const SIGNATURE: [u8; 4] = *b"DIRC";
const VERSION: u32 = 2;
/// `offsetof(struct cache_entry, name)` — the ten u32 fields + oid +
/// flags.
const ENTRY_FIXED: usize = 62;
const TRAILER_LEN: usize = 20;

/// One entry to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexEntry<'a> {
    /// Slash-separated path relative to the worktree (`a/b.txt`).
    pub path: &'a [u8],
    /// The blob's object id.
    pub oid: [u8; 20],
    /// File mode (`100644`, `100755`, `120000`, `160000`).
    pub mode: u32,
    /// File size in bytes.
    pub size: u32,
    /// Modification time, UTC seconds since the epoch (also used as
    /// ctime — see the module docs).
    pub mtime: u32,
}

/// One parsed entry (owned path, no borrowed lifetime).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRecord {
    /// Path bytes (validated).
    pub path: Vec<u8>,
    /// Blob id.
    pub oid: [u8; 20],
    /// Mode.
    pub mode: u32,
    /// Size in bytes.
    pub size: u32,
    /// Modification time.
    pub mtime: u32,
    /// Creation time (what the writer stored; equals `mtime` for us).
    pub ctime: u32,
}

/// A parsed index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Index {
    /// Entries in git's byte-wise path order.
    pub entries: Vec<IndexRecord>,
}

/// Serialize the v2 index with its trailing SHA-1. Entries are sorted
/// byte-wise; duplicates are refused.
pub fn encode_index(entries: &[IndexEntry<'_>]) -> Result<Vec<u8>, Error> {
    if entries.len() > MAX_INDEX_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    let mut sorted = entries.to_vec();
    for entry in &sorted {
        validate_path(entry.path)?;
        if Mode::from_git_mode(entry.mode).is_none() {
            return Err(Error::BadMode);
        }
    }
    sorted.sort_by(|a, b| a.path.cmp(b.path));

    let mut out = Vec::new();
    out.extend_from_slice(&SIGNATURE);
    out.extend_from_slice(&VERSION.to_be_bytes());
    let count = u32::try_from(sorted.len()).map_err(|_| Error::TooManyEntries)?;
    out.extend_from_slice(&count.to_be_bytes());

    let mut previous: Option<&[u8]> = None;
    for entry in &sorted {
        if previous == Some(entry.path) {
            return Err(Error::DuplicateEntry);
        }
        previous = Some(entry.path);

        // ctime sec + nsec, mtime sec + nsec, dev, ino, mode, uid, gid,
        // size — see the module docs for the placeholders.
        push_u32(&mut out, entry.mtime); // ctime
        push_u32(&mut out, 0); // ctime ns
        push_u32(&mut out, entry.mtime); // mtime
        push_u32(&mut out, 0); // mtime ns
        push_u32(&mut out, 0); // dev
        push_u32(&mut out, 0); // ino
        push_u32(&mut out, entry.mode);
        push_u32(&mut out, 0); // uid
        push_u32(&mut out, 0); // gid
        push_u32(&mut out, entry.size);
        out.extend_from_slice(&entry.oid);

        let namelen = u16::try_from(entry.path.len()).map_err(|_| Error::PathTooLong)?;
        out.extend_from_slice(&namelen.to_be_bytes()); // flags: stage 0, no extended
        out.extend_from_slice(entry.path);

        let fixed = ENTRY_FIXED
            .checked_add(entry.path.len())
            .ok_or(Error::PathTooLong)?;
        let total = fixed.checked_add(8).ok_or(Error::PathTooLong)? & !7usize;
        out.extend(core::iter::repeat_n(0u8, total - fixed));
    }

    let checksum = hash(&out);
    out.extend_from_slice(&checksum);
    Ok(out)
}

/// Parse and validate a v2 index: signature, version, entry structure,
/// padding, sortedness, trailing SHA-1 and no bytes between the last
/// entry and the trailer.
pub fn parse_index(data: &[u8]) -> Result<Index, Error> {
    if data.len() < 12 + TRAILER_LEN {
        return Err(Error::BadIndex);
    }
    if data.get(..4) != Some(SIGNATURE.as_slice()) {
        return Err(Error::BadIndexSignature);
    }
    let version = be32_at(data, 4)?;
    if version != VERSION {
        return Err(Error::UnsupportedIndexVersion(version));
    }
    let count = be32_at(data, 8)? as usize;
    if count > MAX_INDEX_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    // The smallest entry is 64 bytes; refuse an absurd count before
    // reserving anything for it.
    let payload_end = data.len() - TRAILER_LEN;
    let minimum = count
        .checked_mul(64)
        .and_then(|v| v.checked_add(12))
        .ok_or(Error::BadIndex)?;
    if minimum > payload_end {
        return Err(Error::BadIndex);
    }

    let mut entries = Vec::with_capacity(count);
    let mut offset = 12usize;
    let mut previous: Option<Vec<u8>> = None;
    for _ in 0..count {
        let fixed_end = offset.checked_add(ENTRY_FIXED).ok_or(Error::BadIndex)?;
        let fixed = data.get(offset..fixed_end).ok_or(Error::BadIndex)?;
        let ctime = be32_at(fixed, 0)?;
        let mtime = be32_at(fixed, 8)?;
        let mode = be32_at(fixed, 24)?;
        let size = be32_at(fixed, 36)?;
        let oid_bytes = fixed.get(40..60).ok_or(Error::BadIndex)?;
        let mut oid = [0u8; 20];
        oid.copy_from_slice(oid_bytes);
        if Mode::from_git_mode(mode).is_none() {
            return Err(Error::BadMode);
        }
        let flags = u16::from_be_bytes(
            fixed
                .get(60..62)
                .ok_or(Error::BadIndex)?
                .try_into()
                .map_err(|_| Error::BadIndex)?,
        );
        if flags & 0x4000 != 0 {
            return Err(Error::ExtendedFlags);
        }
        if flags & 0x3000 != 0 {
            return Err(Error::BadIndex); // merge stages are not written here
        }
        let namelen = usize::from(flags & 0x0FFF);
        if namelen == 0 || namelen >= 0xFFF {
            return Err(Error::BadName);
        }
        let entry_size = ENTRY_FIXED
            .checked_add(namelen)
            .and_then(|v| v.checked_add(8))
            .ok_or(Error::BadIndex)?
            & !7usize;
        let entry_end = offset.checked_add(entry_size).ok_or(Error::BadIndex)?;
        if entry_end > payload_end {
            return Err(Error::BadIndex);
        }
        let name_start = offset.checked_add(ENTRY_FIXED).ok_or(Error::BadIndex)?;
        let name_end = name_start.checked_add(namelen).ok_or(Error::BadIndex)?;
        let path = data.get(name_start..name_end).ok_or(Error::BadIndex)?;
        validate_path(path)?;
        // Everything from the end of the name to the entry boundary is
        // NUL padding in a git-written index.
        if data
            .get(name_end..entry_end)
            .ok_or(Error::BadIndex)?
            .iter()
            .any(|&b| b != 0)
        {
            return Err(Error::BadIndex);
        }

        if let Some(prev) = &previous {
            match path.cmp(prev.as_slice()) {
                core::cmp::Ordering::Greater => {}
                core::cmp::Ordering::Equal => return Err(Error::DuplicateEntry),
                core::cmp::Ordering::Less => return Err(Error::UnsortedIndex),
            }
        }
        let owned = path.to_vec();
        previous = Some(owned.clone());
        entries.push(IndexRecord {
            path: owned,
            oid,
            mode,
            size,
            mtime,
            ctime,
        });
        offset = entry_end;
    }
    if offset != payload_end {
        return Err(Error::BadIndex);
    }

    let expected = data.get(payload_end..).ok_or(Error::BadIndex)?;
    let checksum = hash(data.get(..payload_end).ok_or(Error::BadIndex)?);
    if expected != checksum.as_slice() {
        return Err(Error::ChecksumMismatch);
    }
    Ok(Index { entries })
}

/// A path must be relative, slash-separated, with no empty, `.` or `..`
/// component, no NUL and at most [`MAX_INDEX_PATH`] bytes.
fn validate_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty() || path.len() > MAX_INDEX_PATH || path.contains(&0) {
        return Err(Error::BadName);
    }
    if path.first() == Some(&b'/') || path.last() == Some(&b'/') {
        return Err(Error::BadName);
    }
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(Error::BadName);
        }
    }
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn be32_at(data: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = data
        .get(offset..offset + 4)
        .ok_or(Error::BadIndex)?
        .try_into()
        .map_err(|_| Error::BadIndex)?;
    Ok(u32::from_be_bytes(bytes))
}

fn hash(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Sha1::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut oid = [0u8; 20];
    oid.copy_from_slice(digest.as_slice());
    oid
}
