//! G4/G5: write the fetched repository's **local object store** —
//! `.git/HEAD`, `.git/refs/heads/main`, `objects/xx/…` loose objects and
//! the v2 index — onto the FAT16 volume, then make **one local commit**
//! on top of the fetched head (docs/git-ssh-deps.md §A.4, milestone 3).
//!
//! This runs only after the full checkout succeeded and only with a
//! disk attached (`smoke-install`); the diskless boot never calls it and
//! prints nothing, so the main smoke's marker chain is untouched.
//!
//! # What is written
//!
//! 1. `.git/HEAD` = `ref: refs/heads/main\n`, `.git/refs/heads/main` =
//!    the fetched head's 40-hex id (`git-store::encode_head` /
//!    `encode_ref`).
//! 2. One loose object per decoded pack object (commit, trees, blobs):
//!    re-encode `<type> <size>\0<data>`, assert the SHA-1 equals the
//!    decoded object id, deflate, write `objects/xx/…`. Bodies are
//!    encoded **one object at a time** so peak heap is the pack it
//!    already holds plus one preimage + its deflate output — never the
//!    whole pack re-encoded at once.
//! 3. `.git/index` (v2) for every checked-out path: the fetched tree's
//!    oid/mode, the blob's size, and the RTC epoch as mtime/ctime (the
//!    FAT volume has no inode semantics — see `git_store::index`).
//! 4. The tree objects are **rebuilt** from those paths
//!    (`git_store::build_tree_hierarchy`): the rebuilt root must equal
//!    the fetched commit's tree id and every rebuilt tree must be
//!    byte-identical to the fetched tree object — the strongest check
//!    that the decoder, the writer and git's ordering rule agree.
//! 5. A commit object `tree <rebuilt-root>`, `parent <fetched-head>`,
//!    `author`/`committer` `reemplazo <reemplazo@localhost> <RTC epoch>
//!    +0000`, message `reemplazo: local commit\n`; written as a loose
//!    object and `refs/heads/main` moved to it.
//!
//! # Proof
//!
//! A **fresh mount** (new `fat::Fat16` over a new block adapter) then
//! reads everything back: `HEAD` byte-exact, the ref equal to the new
//! commit id, the index parsed (checksum + entry count + every
//! path/oid/mode), the new commit inflated and re-hashed, its `tree`
//! line equal to the rebuilt root, and every fetched object file
//! inflated and re-hashed to the id its path encodes. Any mismatch is
//! `FATAL: git: …` + halt — `GIT_STORE_OK` is printed only after all of
//! it passes.
//!
//! The block adapter is a thin mirror of `fs::AtaDisk` (same PIO
//! contract: whole 512-byte sectors, capacity-checked): the two proofs
//! own their adapters independently, and the rule of three says a third
//! user is what justifies extracting a shared one.
//!
//! # Bounds
//!
//! Object count ≤ [`MAX_OBJECTS`], tree entries ≤ [`MAX_TREE_ENTRIES`],
//! depth ≤ [`MAX_DEPTH`], path ≤ [`PATH_CAP`], one read-back file ≤
//! [`READ_CAP`] (the largest blob in this repo is ~160 KiB). Every
//! limit is checked before the allocation or the write it bounds.

use crate::ata;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::ptr::addr_of_mut;
use git_pack::{EntryMode, Kind as PackKind};
use git_store::{
    IndexEntry, Kind as StoreKind, Mode, PathEntry, Signature, build_tree_hierarchy, decode_loose,
    encode_commit, encode_head, encode_index, encode_loose, encode_ref, loose_path, parse_index,
    parse_ref,
};

/// Tree nesting cap (the fetch's walk uses the same bound).
const MAX_DEPTH: usize = 16;
/// Entries the store will index (the fetch caps the tree at 4096 too).
const MAX_TREE_ENTRIES: usize = 4096;
/// Full path cap (the checkout writes at most this many bytes).
const PATH_CAP: usize = 255;
/// Objects the store will write (the fetch already caps the pack).
const MAX_OBJECTS: usize = 10_000;
/// Read-back buffer: one file at a time, comfortably over this repo's
/// largest compressed blob (~160 KiB). Anything larger is a hard
/// failure, never a truncated "pass".
const READ_CAP: usize = 512 * 1024;
/// The local commit's message (ends in LF, as git writes it).
const COMMIT_MESSAGE: &[u8] = b"reemplazo: local commit\n";
/// Identity used for the local commit: the OS itself, no invented user.
const IDENT_NAME: &[u8] = b"reemplazo";
const IDENT_EMAIL: &[u8] = b"reemplazo@localhost";
/// Fixed store paths.
const HEAD_PATH: &str = "/.git/HEAD";
const REF_PATH: &str = "/.git/refs/heads/main";
const SHALLOW_PATH: &str = "/.git/shallow";
const INDEX_PATH: &str = "/.git/index";
/// Sanitizer buffer for one logged path.
const SANITIZE_CAP: usize = 128;

/// Single-use read-back storage (the `RESPONSE`/`READ_BACK` idiom): the
/// boot path is single-core and interrupt 0 never touches it.
static mut SCRATCH: [u8; READ_CAP] = [0; READ_CAP];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: git: store: {msg}");
    crate::halt()
}

fn fatal_fat(e: fat::Error) -> ! {
    serial_println!("FATAL: git: store: {:?}", e);
    crate::halt()
}

/// The kernel's ATA drive as a `fat::BlockDevice` — the write adapter
/// for this proof (see the module docs for why it mirrors
/// `fs::AtaDisk` instead of sharing it).
///
/// Unlike `fs::AtaDisk`, this adapter keeps a small **coherent sector
/// cache**: writing 180 loose objects means resolving
/// `.git/objects/xx/<name>` 180 times, and `fat`'s directory scan
/// re-reads every 32-byte entry — one PIO sector command per entry
/// without a cache, which dominated the milestone's first run
/// (~105 ms/object measured). The cache is sound here because this
/// adapter is the *only* live user of the drive while the store runs
/// (the checkout's adapter is already gone), writes go to the device
/// first and then update the cached copy, and each proof phase mounts a
/// fresh adapter, so nothing stale survives a remount.
struct GitDisk<'a> {
    drive: &'a ata::Drive,
    cache: RefCell<SectorCache>,
}

/// Direct-mapped sector cache: 32 slots (16 KiB) — enough to hold the
/// sectors of a 256-entry `.git/objects` directory plus the FAT and the
/// current file's data, so repeated path scans hit instead of issuing
/// one PIO command per directory entry. `keys` stores `sector + 1`
/// (0 = empty).
struct SectorCache {
    keys: [u64; SECTOR_CACHE_SLOTS],
    data: [[u8; 512]; SECTOR_CACHE_SLOTS],
}

const SECTOR_CACHE_SLOTS: usize = 32;

impl SectorCache {
    const fn new() -> SectorCache {
        SectorCache {
            keys: [0; SECTOR_CACHE_SLOTS],
            data: [[0; 512]; SECTOR_CACHE_SLOTS],
        }
    }

    fn slot(sector: u64) -> usize {
        // `% 16` of a u64 always fits a usize on the targets we build.
        usize::try_from(sector % SECTOR_CACHE_SLOTS as u64).unwrap_or(0)
    }
}

impl GitDisk<'_> {
    fn lba(sector: u64) -> Result<u32, fat::Error> {
        u32::try_from(sector).map_err(|_| fat::Error::OutOfRange)
    }
}

impl fat::BlockDevice for GitDisk<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.drive.sectors) * 512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.size_bytes(), offset, buf.len())?;
        let first = offset / 512;
        let mut cache = self.cache.borrow_mut();
        for (index, chunk) in buf.chunks_mut(512).enumerate() {
            let sector = first + index as u64;
            let slot = SectorCache::slot(sector);
            if cache.keys[slot] != sector + 1 {
                let lba = GitDisk::lba(sector)?;
                if !self.drive.read_sectors(lba, &mut cache.data[slot]) {
                    return Err(fat::Error::Read);
                }
                cache.keys[slot] = sector + 1;
            }
            chunk.copy_from_slice(&cache.data[slot]);
        }
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), fat::Error> {
        // Same contract as `read_at`: whole sectors only, range-checked
        // against the IDENTIFY-reported capacity (which `write_sectors`
        // re-checks on the device side — both ends fail closed).
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.size_bytes(), offset, buf.len())?;
        let first = offset / 512;
        let mut cache = self.cache.borrow_mut();
        for (index, chunk) in buf.chunks(512).enumerate() {
            let sector = first + index as u64;
            let lba = GitDisk::lba(sector)?;
            if !self.drive.write_sectors(lba, chunk) {
                // The device state is unknown now: drop the cached copy
                // rather than let a later read serve a stale sector.
                cache.keys[SectorCache::slot(sector)] = 0;
                return Err(fat::Error::Write);
            }
            let slot = SectorCache::slot(sector);
            cache.data[slot].copy_from_slice(chunk);
            cache.keys[slot] = sector + 1;
        }
        Ok(())
    }
}

/// One entry of the fetched tree, as the store needs it.
struct Entry {
    path: Vec<u8>,
    mode: Mode,
    oid: [u8; 20],
}

/// One depth-first frame while rebuilding the entry list.
struct Frame {
    tree: usize,
    next: usize,
    prefix: usize,
}

/// Walk the fetched commit's tree iteratively and collect **every**
/// entry (blobs, executables, symlinks, gitlinks) with its mode and id.
/// The walk is the same shape as `git_fetch`'s checkout walk, but this
/// one must also see the entries the checkout skips: the index and the
/// rebuilt trees have to match git's tree exactly, symlinks included.
fn collect_entries(
    objects: &[git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
    root: &[u8; 20],
) -> Vec<Entry> {
    let Some(root_idx) = by_oid.get(root).copied() else {
        fatal("fetched tree is not in the pack");
    };
    let mut frames: Vec<Frame> = Vec::new();
    frames.push(Frame {
        tree: root_idx,
        next: 0,
        prefix: 0,
    });
    let mut path: Vec<u8> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();

    while let Some(frame) = frames.last_mut() {
        let tree_data = match objects.get(frame.tree) {
            Some(tree) if tree.kind == PackKind::Tree => tree.data.as_slice(),
            Some(_) => fatal("tree entry points at a non-tree object"),
            None => fatal("tree object index out of range"),
        };
        if frame.next >= tree_data.len() {
            if let Some(popped) = frames.pop() {
                path.truncate(popped.prefix);
            }
            continue;
        }
        let entry_start = frame.next;
        let Some(tail) = tree_data.get(entry_start..) else {
            fatal("tree entry offset out of range");
        };
        let (entry, consumed) = match git_pack::parse_tree_entry(tail) {
            Ok(parsed) => parsed,
            Err(e) => {
                serial_println!("FATAL: git: store: malformed tree entry: {e:?}");
                crate::halt();
            }
        };
        frame.next = match entry_start.checked_add(consumed) {
            Some(next) => next,
            None => fatal("tree entry offset overflow"),
        };
        if entries.len() >= MAX_TREE_ENTRIES {
            fatal("tree exceeds the store's entry bound");
        }
        match entry.mode {
            EntryMode::Tree => {
                let Some(child) = by_oid.get(&entry.oid).copied() else {
                    fatal("tree entry points at an object absent from the pack");
                };
                if frames.len() >= MAX_DEPTH {
                    fatal("tree exceeds the depth bound");
                }
                if path.len() + entry.name.len() + 1 > PATH_CAP {
                    fatal("tree path exceeds the path bound");
                }
                let prefix = path.len();
                path.extend_from_slice(entry.name);
                path.push(b'/');
                frames.push(Frame {
                    tree: child,
                    next: 0,
                    prefix,
                });
            }
            EntryMode::Blob | EntryMode::Executable | EntryMode::Symlink => {
                path.extend_from_slice(entry.name);
                if path.len() > PATH_CAP {
                    fatal("tree path exceeds the path bound");
                }
                let Some(&blob_idx) = by_oid.get(&entry.oid) else {
                    fatal("tree entry points at a blob absent from the pack");
                };
                if objects.get(blob_idx).map(|o| o.kind) != Some(PackKind::Blob) {
                    fatal("tree entry points at a non-blob object");
                }
                entries.push(Entry {
                    path: path.clone(),
                    mode: store_mode(entry.mode),
                    oid: entry.oid,
                });
                path.truncate(path.len() - entry.name.len());
            }
            EntryMode::Gitlink => {
                path.extend_from_slice(entry.name);
                if path.len() > PATH_CAP {
                    fatal("tree path exceeds the path bound");
                }
                entries.push(Entry {
                    path: path.clone(),
                    mode: Mode::Gitlink,
                    oid: entry.oid,
                });
                path.truncate(path.len() - entry.name.len());
            }
        }
    }
    entries
}

fn store_mode(mode: EntryMode) -> Mode {
    match mode {
        EntryMode::Tree => Mode::Tree,
        EntryMode::Blob => Mode::Blob,
        EntryMode::Executable => Mode::Executable,
        EntryMode::Symlink => Mode::Symlink,
        EntryMode::Gitlink => Mode::Gitlink,
    }
}

fn pack_kind(kind: PackKind) -> StoreKind {
    match kind {
        PackKind::Commit => StoreKind::Commit,
        PackKind::Tree => StoreKind::Tree,
        PackKind::Blob => StoreKind::Blob,
        PackKind::Tag => StoreKind::Tag,
    }
}

/// The blob's size, read from the pack object the tree points at
/// (the checkout wrote those exact bytes, so this is the on-disk size).
fn blob_size(
    objects: &[git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
    oid: &[u8; 20],
) -> u32 {
    let Some(&index) = by_oid.get(oid) else {
        fatal("index entry points at an object absent from the pack");
    };
    let Some(object) = objects.get(index) else {
        fatal("object index out of range");
    };
    match u32::try_from(object.data.len()) {
        Ok(size) => size,
        Err(_) => fatal("object is too large for the index size field"),
    }
}

/// Cross-check the checkout against the tree walk: every regular file
/// the checkout wrote must be a tree entry and its bytes must hash to
/// that entry's oid. A missing or altered file fails here, before the
/// store claims success.
fn verify_checkout(
    entries: &[Entry],
    files: &[(Vec<u8>, &[u8])],
    objects: &[git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
) {
    let mut checked = 0usize;
    for entry in entries {
        match entry.mode {
            Mode::Blob | Mode::Executable => {
                let Some((_, data)) = files
                    .iter()
                    .find(|(path, _)| path.as_slice() == entry.path.as_slice())
                else {
                    fatal("a checked-out file is absent from the fetched tree");
                };
                if git_pack::object_id(PackKind::Blob, data) != entry.oid {
                    fatal("a checked-out file does not hash to its tree entry");
                }
                let _ = blob_size(objects, by_oid, &entry.oid);
                checked += 1;
            }
            Mode::Symlink => {
                let _ = blob_size(objects, by_oid, &entry.oid);
            }
            // A gitlink's commit is not in a shallow pack; nothing to
            // check against its blob (there is none).
            Mode::Gitlink | Mode::Tree => {}
        }
    }
    if checked != files.len() {
        fatal("the fetched tree and the checkout wrote different file sets");
    }
}

/// Write `/.git` + one local commit and prove it from a fresh mount.
pub(crate) fn realize(
    drive: &ata::Drive,
    head: &[u8; 20],
    root: &[u8; 20],
    objects: &[git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
    files: &[(Vec<u8>, &[u8])],
) {
    if objects.len() > MAX_OBJECTS {
        fatal("the pack holds more objects than the store will write");
    }
    let entries = collect_entries(objects, by_oid, root);
    if entries.len() > MAX_TREE_ENTRIES {
        fatal("the tree holds more entries than the store will write");
    }
    verify_checkout(&entries, files, objects, by_oid);

    // One clock read: the commit timestamp, index mtime and FAT stamps
    // all agree (a missing clock falls back to epoch 0, documented).
    let epoch = crate::rtc::now_epoch().unwrap_or(0);
    let epoch_u32 = u32::try_from(epoch).unwrap_or(u32::MAX);
    let login = i64::try_from(epoch).unwrap_or(i64::MAX);
    let stamp = stamp_from_epoch(epoch);

    // --- write phase -------------------------------------------------
    let (loose_count, loose_bytes, index_entries, commit_oid, tree_entries) = {
        let disk = GitDisk {
            drive,
            cache: RefCell::new(SectorCache::new()),
        };
        let fs = match fat::Fat16::mount(&disk) {
            Ok(fs) => fs,
            Err(e) => fatal_fat(e),
        };
        for dir in ["/.git", "/.git/objects", "/.git/refs/heads"] {
            if let Err(e) = fs.create_dir_all(dir, stamp) {
                serial_println!("FATAL: git: store: mkdir {dir} refused: {e:?}");
                crate::halt();
            }
        }

        // Symbolic HEAD + direct ref at the fetched head.
        let head_bytes = match encode_head(b"main") {
            Ok(bytes) => bytes,
            Err(_) => fatal("cannot encode HEAD"),
        };
        if let Err(e) = fs.write_file_all(HEAD_PATH, &head_bytes, stamp) {
            fatal_fat(e);
        }
        if let Err(e) = fs.write_file_all(REF_PATH, &encode_ref(head), stamp) {
            fatal_fat(e);
        }
        // The fetched head is a shallow boundary (`deepen 1`): a real
        // `git clone --depth 1` writes `.git/shallow` so the walk stops
        // there instead of chasing parents that are not in the pack.
        // Without it the local commit's parent is a "missing object".
        let mut shallow = [0u8; 41];
        shallow[..40].copy_from_slice(&git_store::hex_oid(head));
        shallow[40] = b'\n';
        if let Err(e) = fs.write_file_all(SHALLOW_PATH, &shallow, stamp) {
            fatal_fat(e);
        }

        // Every decoded object as a loose object, one at a time.
        let mut path_buf = [0u8; 128];
        let mut loose_count = 0usize;
        let mut loose_bytes = 0usize;
        for object in objects {
            let loose = match encode_loose(pack_kind(object.kind), &object.data) {
                Ok(loose) => loose,
                Err(e) => {
                    serial_println!("FATAL: git: store: loose encode refused: {e:?}");
                    crate::halt();
                }
            };
            if loose.oid != object.oid() {
                fatal("encoded object id differs from the decoded one");
            }
            let path = git_path(&loose_path(&loose.oid), &mut path_buf);
            if let Err(e) = fs.write_file_all(path, &loose.compressed, stamp) {
                serial_println!(
                    "FATAL: git: store: loose write {path} ({:?}, {} data bytes, {} compressed) refused: {e:?}",
                    object.kind,
                    object.data.len(),
                    loose.compressed.len()
                );
                crate::halt();
            }
            loose_count += 1;
            loose_bytes = loose_bytes.saturating_add(loose.compressed.len());
        }

        // Index for every checked-out entry (v2, checksummed).
        let mut index: Vec<IndexEntry> = Vec::new();
        for entry in &entries {
            let size = match entry.mode {
                Mode::Gitlink => 0,
                _ => blob_size(objects, by_oid, &entry.oid),
            };
            index.push(IndexEntry {
                path: &entry.path,
                oid: entry.oid,
                mode: entry.mode.octal(),
                size,
                mtime: epoch_u32,
            });
        }
        let index_bytes = match encode_index(&index) {
            Ok(bytes) => bytes,
            Err(e) => {
                serial_println!("FATAL: git: store: index encode refused: {e:?}");
                crate::halt();
            }
        };
        if let Err(e) = fs.write_file_all(INDEX_PATH, &index_bytes, stamp) {
            fatal_fat(e);
        }

        // Rebuild the trees from the index data and require exact
        // agreement with the fetched objects.
        let path_entries: Vec<PathEntry> = entries
            .iter()
            .map(|entry| PathEntry {
                path: &entry.path,
                mode: entry.mode,
                oid: entry.oid,
            })
            .collect();
        let built = match build_tree_hierarchy(&path_entries) {
            Ok(built) => built,
            Err(e) => {
                serial_println!("FATAL: git: store: tree rebuild refused: {e:?}");
                crate::halt();
            }
        };
        if built.root != *root {
            let mut rebuilt_hex = [0u8; 40];
            rebuilt_hex.copy_from_slice(&git_store::hex_oid(&built.root));
            let mut fetched_hex = [0u8; 40];
            fetched_hex.copy_from_slice(&git_store::hex_oid(root));
            serial_println!(
                "FATAL: git: store: rebuilt root {} != fetched tree {}",
                core::str::from_utf8(&rebuilt_hex).unwrap_or("?"),
                core::str::from_utf8(&fetched_hex).unwrap_or("?")
            );
            crate::halt();
        }
        for (oid, bytes) in &built.trees {
            let Some(&object_index) = by_oid.get(oid) else {
                fatal("a rebuilt tree is absent from the fetched pack");
            };
            let Some(object) = objects.get(object_index) else {
                fatal("tree object index out of range");
            };
            if object.kind != PackKind::Tree || object.data != *bytes {
                fatal("a rebuilt tree differs from the fetched tree bytes");
            }
        }

        // The local commit: parent = fetched head, tree = rebuilt root.
        let signature = Signature {
            name: IDENT_NAME,
            email: IDENT_EMAIL,
            epoch: login,
        };
        let commit_bytes = match encode_commit(
            &built.root,
            &[*head],
            &signature,
            &signature,
            COMMIT_MESSAGE,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                serial_println!("FATAL: git: store: commit encode refused: {e:?}");
                crate::halt();
            }
        };
        let commit = match encode_loose(StoreKind::Commit, &commit_bytes) {
            Ok(commit) => commit,
            Err(e) => {
                serial_println!("FATAL: git: store: commit object refused: {e:?}");
                crate::halt();
            }
        };
        let path = git_path(&loose_path(&commit.oid), &mut path_buf);
        if let Err(e) = fs.write_file_all(path, &commit.compressed, stamp) {
            fatal_fat(e);
        }
        if let Err(e) = fs.write_file_all(REF_PATH, &encode_ref(&commit.oid), stamp) {
            fatal_fat(e);
        }

        (
            loose_count,
            loose_bytes,
            index.len(),
            commit.oid,
            built.trees.len(),
        )
    };

    let mut oid_hex = [0u8; 40];
    oid_hex.copy_from_slice(&git_store::hex_oid(&commit_oid));
    let mut root_hex = [0u8; 40];
    root_hex.copy_from_slice(&git_store::hex_oid(root));
    let (Some(commit_hex), Some(tree_hex)) = (
        core::str::from_utf8(&oid_hex).ok(),
        core::str::from_utf8(&root_hex).ok(),
    ) else {
        fatal("object id is not ASCII");
    };
    serial_println!(
        "git: store: {loose_count} fetched object(s) + 1 local commit written as loose objects ({loose_bytes} fetched bytes), index {index_entries} entries, {tree_entries} tree(s) rebuilt, tree {tree_hex}, commit {commit_hex}"
    );

    // --- verify phase (fresh mount) ---------------------------------
    let disk = GitDisk {
        drive,
        cache: RefCell::new(SectorCache::new()),
    };
    let fs = match fat::Fat16::mount(&disk) {
        Ok(fs) => fs,
        Err(e) => fatal_fat(e),
    };
    // SAFETY: single-use static (see `SCRATCH`).
    let scratch = unsafe { &mut *addr_of_mut!(SCRATCH) };

    // HEAD is exactly the symbolic ref we wrote.
    let expected_head = match encode_head(b"main") {
        Ok(bytes) => bytes,
        Err(_) => fatal("cannot encode HEAD"),
    };
    let n = read_into(&fs, HEAD_PATH, scratch);
    if scratch.get(..n) != Some(expected_head.as_slice()) {
        fatal("HEAD read back does not match");
    }

    // The shallow boundary names the fetched head (a real
    // `clone --depth 1` writes this file; the local commit's parent must
    // not look like a missing object).
    let n = read_into(&fs, SHALLOW_PATH, scratch);
    match parse_ref(scratch.get(..n).unwrap_or_default()) {
        Ok(oid) if oid == *head => {}
        _ => fatal(".git/shallow read back does not name the fetched head"),
    }

    // The ref names the local commit, with a valid 40-hex id.
    let n = read_into(&fs, REF_PATH, scratch);
    match parse_ref(scratch.get(..n).unwrap_or_default()) {
        Ok(oid) if oid == commit_oid => {}
        _ => fatal("refs/heads/main read back does not name the local commit"),
    }

    // The index parses (checksum), covers every entry, and its paths,
    // modes and oids are the ones the tree walk produced.
    let n = read_into(&fs, INDEX_PATH, scratch);
    let parsed = match parse_index(scratch.get(..n).unwrap_or_default()) {
        Ok(index) => index,
        Err(e) => {
            serial_println!("FATAL: git: store: index read back refused: {e:?}");
            crate::halt();
        }
    };
    if parsed.entries.len() != entries.len() {
        fatal("index read back has a different entry count");
    }
    for record in &parsed.entries {
        let Some(entry) = entries
            .iter()
            .find(|entry| entry.path.as_slice() == record.path.as_slice())
        else {
            fatal("index read back names a path the tree does not");
        };
        if record.oid != entry.oid || record.mode != entry.mode.octal() {
            fatal("index read back disagrees with the tree entry");
        }
    }

    // The new commit inflates, re-hashes, and its tree line is the
    // rebuilt root.
    let mut commit_path_buf = [0u8; 128];
    let commit_path = git_path(&loose_path(&commit_oid), &mut commit_path_buf);
    let n = read_into(&fs, commit_path, scratch);
    let object = match decode_loose(scratch.get(..n).unwrap_or_default()) {
        Ok(object) => object,
        Err(e) => {
            serial_println!("FATAL: git: store: commit read back refused: {e:?}");
            crate::halt();
        }
    };
    if object.kind != StoreKind::Commit || object.oid != commit_oid {
        fatal("commit read back does not re-hash to its own id");
    }
    match git_pack::parse_commit_tree(&object.data) {
        Ok(tree) if tree == *root => {}
        _ => fatal("commit read back does not name the rebuilt root tree"),
    }

    // Every fetched object file inflates and re-hashes to its path id.
    let mut verified = 0usize;
    let mut path_buf = [0u8; 128];
    for object in objects {
        let oid = object.oid();
        let path = git_path(&loose_path(&oid), &mut path_buf);
        let n = read_into(&fs, path, scratch);
        let decoded = match decode_loose(scratch.get(..n).unwrap_or_default()) {
            Ok(decoded) => decoded,
            Err(e) => {
                serial_println!("FATAL: git: store: loose object read back refused: {e:?}");
                crate::halt();
            }
        };
        if decoded.oid != oid
            || decoded.kind != pack_kind(object.kind)
            || decoded.data != object.data
        {
            fatal("a loose object read back does not match the fetched object");
        }
        verified += 1;
    }
    if verified != objects.len() {
        fatal("not every loose object was verified");
    }

    // A sanitized sample of the paths proves it is this repository.
    let mut sample_buf = [0u8; SANITIZE_CAP];
    for entry in entries.iter().take(2) {
        let name = crate::git::sanitize(&entry.path, &mut sample_buf);
        serial_println!("git: store: file: {name}");
    }

    serial_println!(
        "git: store: verified {verified} object(s) + index ({index_entries} entries) from a fresh mount"
    );
    serial_println!("GIT_STORE_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// Build `/.git/<rel>` in `buf` (rel is the `git-store` relative path,
/// always ASCII) and return it as `&str`.
fn git_path<'a>(rel: &[u8], buf: &'a mut [u8; 128]) -> &'a str {
    let total = match rel.len().checked_add(6) {
        Some(total) => total,
        None => fatal("git path length overflow"),
    };
    if total > buf.len() {
        fatal("git path exceeds the store's buffer");
    }
    buf[..6].copy_from_slice(b"/.git/");
    buf[6..total].copy_from_slice(rel);
    match core::str::from_utf8(&buf[..total]) {
        Ok(path) => path,
        Err(_) => fatal("git path is not UTF-8"),
    }
}

fn read_into<D: fat::BlockDevice + ?Sized>(
    fs: &fat::Fat16<'_, D>,
    path: &str,
    out: &mut [u8],
) -> usize {
    match fs.read_file(path, out) {
        Ok(n) => n,
        Err(e) => fatal_fat(e),
    }
}

fn stamp_from_epoch(epoch: u64) -> fat::Stamp {
    let clock = crate::rtc::from_epoch(epoch);
    fat::Stamp {
        year: clock.year,
        month: clock.month,
        day: clock.day,
        hour: clock.hour,
        minute: clock.minute,
        second: clock.second,
    }
}
