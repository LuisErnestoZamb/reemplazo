//! Build nested tree objects from a flat list of checked-out paths.
//!
//! The kernel has the fetched tree's entries as `(path, mode, oid)`
//! pairs (one per regular file / symlink / gitlink) and needs the
//! **tree objects** for a local commit: one tree per directory, each
//! entry `<mode> SP <name> NUL <oid>` sorted by
//! [`crate::base_name_compare`](crate::base_name_compare) — exactly the
//! serialization [`crate::encode_tree`] performs. This module groups the
//! paths by directory, builds children before parents, and returns the
//! root oid plus every tree's bytes so the caller can write them as
//! loose objects.
//!
//! Rebuilding the tree from the index is also a **cross-check**: if the
//! fetched objects were decoded correctly and the paths/modes/oids are
//! complete, the rebuilt root oid equals the fetched commit's tree oid,
//! and every rebuilt tree's bytes equal the fetched tree object. The
//! kernel's `GIT_STORE_OK` proof asserts exactly that.
//!
//! Bounds: at most [`MAX_TREE_DIRS`] distinct directories, path depth
//! [`MAX_TREE_DEPTH`], paths ≤ [`MAX_PATH`], and the emitted tree bytes
//! are capped by the object-size ceiling.

use crate::object::{Kind, MAX_OBJECT_SIZE, object_oid};
use crate::tree::{Mode, TreeEntry, encode_tree, validate_name};
use crate::{Error, MAX_TREE_ENTRIES};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// Most distinct directories a hierarchy may contain.
pub const MAX_TREE_DIRS: usize = 4096;
/// Deepest path accepted (component count).
pub const MAX_TREE_DEPTH: usize = 64;
/// Longest full path accepted.
pub const MAX_PATH: usize = 4095;

/// One file-like entry of the checked-out tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathEntry<'a> {
    /// Slash-separated relative path (`docs/hardware.md`).
    pub path: &'a [u8],
    /// The entry's mode (blob, executable, symlink or gitlink; never a
    /// subtree).
    pub mode: Mode,
    /// The entry's object id.
    pub oid: [u8; 20],
}

/// Files grouped by their parent directory: `dir -> [(name, mode, oid)]`.
type FilesByDir = BTreeMap<Vec<u8>, Vec<(Vec<u8>, Mode, [u8; 20])>>;
/// Child directory names grouped by parent directory.
type DirsByParent = BTreeMap<Vec<u8>, Vec<Vec<u8>>>;

/// The hierarchy's root id and every tree object built, children before
/// parents (the root is last).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltTrees {
    /// The root tree's id.
    pub root: [u8; 20],
    /// `(oid, serialized tree bytes)` for every directory.
    pub trees: Vec<([u8; 20], Vec<u8>)>,
}

/// Group `entries` into directories and serialize every tree bottom-up.
pub fn build_tree_hierarchy(entries: &[PathEntry<'_>]) -> Result<BuiltTrees, Error> {
    let mut files: FilesByDir = BTreeMap::new();
    let mut subdirs: DirsByParent = BTreeMap::new();

    for entry in entries {
        if entry.mode.is_dir() {
            return Err(Error::BadMode);
        }
        validate_full_path(entry.path)?;
        let mut components: Vec<&[u8]> = entry.path.split(|&b| b == b'/').collect();
        let name = components.pop().ok_or(Error::BadName)?;
        if components.len() > MAX_TREE_DEPTH {
            return Err(Error::TooDeep);
        }

        // Register each ancestor directory under its parent (deduped).
        let mut dir: Vec<u8> = Vec::new();
        for component in components {
            let children = subdirs.entry(dir.clone()).or_default();
            if !children.iter().any(|child| child.as_slice() == component) {
                children.push(component.to_vec());
            }
            if !dir.is_empty() {
                dir.push(b'/');
            }
            dir.extend_from_slice(component);
        }

        let bucket = files.entry(dir).or_default();
        if bucket
            .iter()
            .any(|(existing, _, _)| existing.as_slice() == name)
        {
            return Err(Error::DuplicateEntry);
        }
        bucket.push((name.to_vec(), entry.mode, entry.oid));
        if files.len() > MAX_TREE_DIRS || subdirs.len() > MAX_TREE_DIRS {
            return Err(Error::TooManyEntries);
        }
    }

    let mut trees = Vec::new();
    let mut total = 0usize;
    let root = build_dir(b"", 0, &files, &subdirs, &mut trees, &mut total)?;
    Ok(BuiltTrees { root, trees })
}

fn build_dir(
    dir: &[u8],
    depth: usize,
    files: &FilesByDir,
    subdirs: &DirsByParent,
    out: &mut Vec<([u8; 20], Vec<u8>)>,
    total: &mut usize,
) -> Result<[u8; 20], Error> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::TooDeep);
    }
    let mut entries: Vec<TreeEntry> = Vec::new();
    if let Some(bucket) = files.get(dir) {
        for (name, mode, oid) in bucket {
            entries.push(TreeEntry {
                mode: *mode,
                name,
                oid: *oid,
            });
        }
    }
    if let Some(children) = subdirs.get(dir) {
        if children.len() > MAX_TREE_ENTRIES {
            return Err(Error::TooManyEntries);
        }
        for child in children {
            // `subdirs` is keyed by the *full* parent path, so the
            // recursion needs `dir/child`, not the bare component.
            let mut child_path = Vec::with_capacity(dir.len().saturating_add(1 + child.len()));
            if !dir.is_empty() {
                child_path.extend_from_slice(dir);
                child_path.push(b'/');
            }
            child_path.extend_from_slice(child);
            let oid = build_dir(&child_path, depth + 1, files, subdirs, out, total)?;
            entries.push(TreeEntry {
                mode: Mode::Tree,
                name: child,
                oid,
            });
        }
    }
    if entries.len() > MAX_TREE_ENTRIES {
        return Err(Error::TooManyEntries);
    }
    let bytes = encode_tree(&entries)?;
    *total = total
        .checked_add(bytes.len())
        .ok_or(Error::ObjectTooLarge)?;
    if *total > MAX_OBJECT_SIZE {
        return Err(Error::ObjectTooLarge);
    }
    let oid = object_oid(Kind::Tree, &bytes);
    out.push((oid, bytes));
    Ok(oid)
}

fn validate_full_path(path: &[u8]) -> Result<(), Error> {
    if path.is_empty() {
        return Err(Error::BadName);
    }
    if path.len() > MAX_PATH {
        return Err(Error::PathTooLong);
    }
    if path.first() == Some(&b'/') || path.last() == Some(&b'/') {
        return Err(Error::BadName);
    }
    for component in path.split(|&b| b == b'/') {
        validate_name(component)?;
    }
    Ok(())
}
