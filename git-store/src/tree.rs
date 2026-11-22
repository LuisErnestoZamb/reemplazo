//! git **tree** objects — [`encode_tree`] plus the ordering rule that
//! makes a tree byte-identical to what git writes.
//!
//! Format ([gitformat-objects](https://git-scm.com/docs/gitformat-objects)):
//!
//! ```text
//! tree      = entry*
//! entry     = <mode-octal> SP <name> NUL <20-byte oid>
//! mode      = 40000 | 100644 | 100755 | 120000 | 160000
//! ```
//!
//! Modes are written with **no leading zero** (`40000`, not `040000`) —
//! that is how git emits them, and any other spelling changes the
//! object id. Names are raw bytes with no NUL and no `/`.
//!
//! # Ordering (`base_name_compare`)
//!
//! git sorts tree entries with `base_name_compare` (`tree-walk.h`):
//! the names are compared byte-wise for their common length, then the
//! next byte is compared, with a **directory's end-of-name treated as
//! `/` (0x2F)**. Consequences that trip naive `strcmp` sorting:
//!
//! - a directory `foo` sorts **after** the file `foo.txt` (`/` 0x2F >
//!   `.` 0x2E), while a *file* named `foo` sorts before `foo.txt`
//!   (its virtual byte is NUL, 0x00);
//! - a directory `foo` sorts before `foo0` (`/` < `0`).
//!
//! [`base_name_compare`] implements exactly that rule, and
//! [`encode_tree`] applies it before serializing.

use crate::Error;
use alloc::vec::Vec;
use core::cmp::Ordering;

/// Cap on entries in one tree object (the kernel walk caps a whole tree
/// at 4096 entries, so one directory cannot legitimately exceed that).
pub const MAX_TREE_ENTRIES: usize = 4096;
/// Longest tree-entry name accepted (a POSIX path component).
pub const MAX_NAME_LEN: usize = 255;

/// The five modes a tree entry can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `40000` — a subtree.
    Tree,
    /// `100644` — a regular file.
    Blob,
    /// `100755` — an executable file.
    Executable,
    /// `120000` — a symlink (its blob is the target path).
    Symlink,
    /// `160000` — a gitlink (submodule commit id, no object here).
    Gitlink,
}

impl Mode {
    /// The mode as the octal integer git stores.
    pub fn octal(self) -> u32 {
        match self {
            Mode::Tree => 0o40000,
            Mode::Blob => 0o100644,
            Mode::Executable => 0o100755,
            Mode::Symlink => 0o120000,
            Mode::Gitlink => 0o160000,
        }
    }

    /// The mode as git writes it in a tree entry — no leading zero.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            Mode::Tree => b"40000",
            Mode::Blob => b"100644",
            Mode::Executable => b"100755",
            Mode::Symlink => b"120000",
            Mode::Gitlink => b"160000",
        }
    }

    /// Classify an octal mode value; only git's five modes pass.
    pub fn from_octal(value: u32) -> Option<Mode> {
        match value {
            0o40000 => Some(Mode::Tree),
            0o100644 => Some(Mode::Blob),
            0o100755 => Some(Mode::Executable),
            0o120000 => Some(Mode::Symlink),
            0o160000 => Some(Mode::Gitlink),
            _ => None,
        }
    }

    /// How the index spells the mode (same values, named for the index
    /// reader).
    pub fn from_git_mode(value: u32) -> Option<Mode> {
        Mode::from_octal(value)
    }

    /// Is this a subtree entry?
    pub fn is_dir(self) -> bool {
        matches!(self, Mode::Tree)
    }
}

/// One tree entry to serialize.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeEntry<'a> {
    /// The entry mode.
    pub mode: Mode,
    /// The raw name (validated by [`encode_tree`]).
    pub name: &'a [u8],
    /// The entry's object id.
    pub oid: [u8; 20],
}

/// git's `base_name_compare`: compare two names byte-wise, then compare
/// the byte past the common prefix, treating the end of a **directory**
/// name as `/` (0x2F) and the end of any other name as NUL.
pub fn base_name_compare(a: &[u8], a_dir: bool, b: &[u8], b_dir: bool) -> Ordering {
    let mut i = 0usize;
    while let (Some(&x), Some(&y)) = (a.get(i), b.get(i)) {
        if x != y {
            return x.cmp(&y);
        }
        i += 1;
    }
    // The shorter name ran out (or both did): its next byte is the
    // virtual terminator, `/` only when that entry is a directory.
    let ca = match a.get(i) {
        Some(&byte) => byte,
        None if a_dir => b'/',
        None => 0,
    };
    let cb = match b.get(i) {
        Some(&byte) => byte,
        None if b_dir => b'/',
        None => 0,
    };
    ca.cmp(&cb)
}

/// Validate one tree-entry name: non-empty, at most [`MAX_NAME_LEN`],
/// not `.`/`..`, no NUL, no `/`. Any other byte (UTF-8 included) is
/// legal — git tree names are bytes.
pub fn validate_name(name: &[u8]) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > MAX_NAME_LEN
        || name == b"."
        || name == b".."
        || name.contains(&b'/')
        || name.contains(&0)
    {
        return Err(Error::BadName);
    }
    Ok(())
}

/// Serialize one tree object, sorting the entries by
/// [`base_name_compare`] first. Duplicate names are refused (a tree
/// with two identical names is not a tree git can index).
pub fn encode_tree(entries: &[TreeEntry<'_>]) -> Result<Vec<u8>, Error> {
    if entries.len() > MAX_TREE_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    let mut sorted = entries.to_vec();
    for entry in &sorted {
        validate_name(entry.name)?;
    }
    sorted.sort_by(|a, b| base_name_compare(a.name, a.mode.is_dir(), b.name, b.mode.is_dir()));

    let mut out = Vec::new();
    let mut previous: Option<&[u8]> = None;
    for entry in &sorted {
        if previous == Some(entry.name) {
            return Err(Error::DuplicateEntry);
        }
        previous = Some(entry.name);
        out.extend_from_slice(entry.mode.as_bytes());
        out.push(b' ');
        out.extend_from_slice(entry.name);
        out.push(0);
        out.extend_from_slice(&entry.oid);
    }
    Ok(out)
}
