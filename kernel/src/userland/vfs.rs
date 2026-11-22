//! Bounded user-visible volume for the hito-4 filesystem syscalls.
//!
//! The kernel keeps ownership of `fat` + ATA/AHCI (no IOMMU on the ICH7,
//! FAT16 writes are non-atomic, and the installer must format before a
//! process exists). This module is the *user-visible* side of that rule:
//! a fixed, in-memory FAT-like volume with whole-file slots, so the
//! `Open/Close/Read/Write/Stat/Readdir` ABI has real bytes to move even
//! on the diskless `smoke-user` boot. A future milestone can mount the
//! ATA/AHCI volume behind the same operations without changing the ABI.
//!
//! Everything here is `forbid(unsafe_code)` and uses only atomics:
//! single-core, `int 0x80` runs with IF=0, and relaxed operations are
//! sufficient because no other agent observes the volume mid-syscall.
//! Every bound is a compile-time constant — no heap, no growth by user
//! request, no `unwrap`/`expect` on disk or user data.

#![forbid(unsafe_code)]

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use super::syscall::{EINVAL, EPERM};

/// Longest accepted path, including the leading `/` (ABI cap).
pub const MAX_PATH: usize = 256;
/// Longest single path component (also the `Readdir` name cap).
pub const MAX_NAME: usize = 56;
/// Deepest accepted path (components after the leading `/`).
pub const MAX_DEPTH: usize = 8;
/// Number of volume slots (files and directories combined).
pub const MAX_FILES: usize = 8;
/// Bytes per slot. A user edit is bounded well below a 64 KiB syscall.
pub const FILE_CAP: usize = 4096;
/// Wire size of one `Stat` record: `size:u64 LE`, `kind:u8`, `flags:u8`, pad.
pub const STAT_LEN: usize = 16;
/// Wire size of one `Readdir` record: `kind:u8`, `len:u8`, name (62 B).
pub const DIRENT_LEN: usize = 64;
/// Name bytes inside one `Readdir` record.
pub const DIRENT_NAME: usize = DIRENT_LEN - 2;

/// Kind byte on the wire and in a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    File = 0,
    Dir = 1,
}

impl Kind {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::File),
            1 => Some(Self::Dir),
            _ => None,
        }
    }
}

/// One atomic-backed slot. `used=0` means free; a directory stores no
/// data bytes but participates in path lookup and `Readdir`.
struct Slot {
    used: AtomicU8,
    kind: AtomicU8,
    path: [AtomicU8; MAX_PATH],
    path_len: AtomicUsize,
    data: [AtomicU8; FILE_CAP],
    len: AtomicUsize,
}

impl Slot {
    const fn new() -> Self {
        Self {
            used: AtomicU8::new(0),
            kind: AtomicU8::new(Kind::File as u8),
            path: [const { AtomicU8::new(0) }; MAX_PATH],
            path_len: AtomicUsize::new(0),
            data: [const { AtomicU8::new(0) }; FILE_CAP],
            len: AtomicUsize::new(0),
        }
    }

    fn load_path(&self) -> ([u8; MAX_PATH], usize) {
        let n = self.path_len.load(Ordering::Relaxed).min(MAX_PATH);
        let mut out = [0u8; MAX_PATH];
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = self.path[i].load(Ordering::Relaxed);
        }
        (out, n)
    }

    fn store_path(&self, path: &[u8]) {
        let n = path.len().min(MAX_PATH);
        for (i, b) in path[..n].iter().enumerate() {
            self.path[i].store(*b, Ordering::Relaxed);
        }
        self.path_len.store(n, Ordering::Relaxed);
    }

    fn path_eq(&self, path: &[u8]) -> bool {
        let n = self.path_len.load(Ordering::Relaxed);
        n == path.len() && (0..n).all(|i| self.path[i].load(Ordering::Relaxed) == path[i])
    }

    fn kind(&self) -> Option<Kind> {
        Kind::from_byte(self.kind.load(Ordering::Relaxed))
    }

    fn read(&self, off: usize, out: &mut [u8]) -> usize {
        let len = self.len.load(Ordering::Relaxed).min(FILE_CAP);
        if off >= len {
            return 0;
        }
        let n = out.len().min(len - off);
        for (i, b) in out[..n].iter_mut().enumerate() {
            *b = self.data[off + i].load(Ordering::Relaxed);
        }
        n
    }

    fn write(&self, off: usize, src: &[u8]) -> usize {
        let old = self.len.load(Ordering::Relaxed).min(FILE_CAP);
        let end = match off.checked_add(src.len()) {
            Some(e) => e.min(FILE_CAP),
            None => return 0,
        };
        if off >= FILE_CAP || end <= off {
            return 0;
        }
        let n = end - off;
        for (i, b) in src[..n].iter().enumerate() {
            self.data[off + i].store(*b, Ordering::Relaxed);
        }
        if end > old {
            self.len.store(end, Ordering::Relaxed);
        }
        n
    }

    fn truncate(&self) {
        self.len.store(0, Ordering::Relaxed);
    }
}

static SLOTS: [Slot; MAX_FILES] = [const { Slot::new() }; MAX_FILES];
static INIT: AtomicBool = AtomicBool::new(false);

/// Validate an absolute volume path. This is the *only* path grammar the
/// user ABI accepts: one leading `/`, ASCII graphic components, no `.`,
/// no `..`, no empty component, no backslash/NUL, bounded depth/length.
/// A path escape is a permission failure (`EPERM`); malformed paths are
/// `EINVAL`. Never dereferences user memory — the caller supplies an
/// already-validated `&[u8]`.
pub fn validate_path(path: &[u8]) -> Result<(), i64> {
    if path.is_empty() || path.len() > MAX_PATH || path[0] != b'/' {
        return Err(if path.is_empty() { EINVAL } else { EPERM });
    }
    let mut depth = 0usize;
    let mut comp = 0usize;
    let mut first = 0u8;
    let mut i = 1usize;
    while i <= path.len() {
        let at_end = i == path.len();
        if at_end || path[i] == b'/' {
            if comp == 0 {
                return Err(EINVAL); // "//" or trailing '/'
            }
            if comp > MAX_NAME || depth >= MAX_DEPTH {
                return Err(EINVAL);
            }
            // "." and ".." are the classic volume-escape trick. They are
            // graphic ASCII, so they need their own explicit check.
            if comp == 1 && first == b'.' || comp == 2 && first == b'.' && path[i - 1] == b'.' {
                return Err(EPERM);
            }
            depth += 1;
            comp = 0;
            first = 0;
        } else {
            let b = path[i];
            if b == 0 || b == b'\\' || !(0x21..=0x7e).contains(&b) {
                return Err(EPERM);
            }
            if comp == 0 {
                first = b;
            }
            comp += 1;
        }
        i += 1;
    }
    Ok(())
}

/// True when `path` is a component-prefix of `child` (both validated).
fn is_ancestor(path: &[u8], child: &[u8]) -> bool {
    child.len() > path.len()
        && child.starts_with(path)
        && child[path.len()] == b'/'
        && child[path.len() + 1..].iter().all(|b| *b != b'/')
}

fn find(path: &[u8]) -> Option<usize> {
    SLOTS
        .iter()
        .position(|s| s.used.load(Ordering::Relaxed) != 0 && s.path_eq(path))
}

/// Seed the volume once. The two fixtures give the hito-4 proof a real
/// file to open and a deterministic initial byte string to compare the
/// editor's write-back against. No file is ever created by a boot marker
/// outside the explicit `Open(O_CREAT)` path.
fn seed(path: &[u8], kind: Kind, data: &[u8]) {
    for (idx, slot) in SLOTS.iter().enumerate() {
        if slot.used.load(Ordering::Relaxed) != 0 {
            continue;
        }
        slot.store_path(path);
        slot.kind.store(kind as u8, Ordering::Relaxed);
        if kind == Kind::File {
            let n = data.len().min(FILE_CAP);
            for (i, b) in data[..n].iter().enumerate() {
                slot.data[i].store(*b, Ordering::Relaxed);
            }
            slot.len.store(n, Ordering::Relaxed);
        }
        slot.used.store(1, Ordering::Relaxed);
        let _ = idx;
        return;
    }
}

/// Idempotent volume initialization. Called from every entry point that
/// touches a file so the first user syscall cannot see an empty volume.
pub fn init() {
    if INIT.swap(true, Ordering::Relaxed) {
        return;
    }
    seed(b"/DOC", Kind::Dir, b"");
    seed(
        b"/HELLO.TXT",
        Kind::File,
        b"hello from the userland volume\n",
    );
    seed(b"/NOTES.TXT", Kind::File, b"reemplazo user editor\n");
    seed(b"/DOC/README.TXT", Kind::File, b"nested userland file\n");
}

/// Look up `path`. `Err` uses the ABI's existing errnos; `EPERM` is
/// reserved for escaping the volume via a directory slot.
pub fn lookup(path: &[u8]) -> Result<usize, i64> {
    init();
    validate_path(path)?;
    find(path).ok_or(EINVAL)
}

/// Create a new file slot. Only `Open(O_CREAT)` reaches this; the parent
/// must be an existing directory (or the volume root). A path whose
/// parent is a file is refused with `EPERM`.
pub fn create(path: &[u8]) -> Result<usize, i64> {
    init();
    validate_path(path)?;
    if find(path).is_some() {
        return Err(EINVAL);
    }
    if let Some(slash) = path.iter().rposition(|b| *b == b'/')
        && slash > 0
    {
        let parent = &path[..slash];
        let slot = find(parent).ok_or(EINVAL)?;
        if SLOTS[slot].kind() != Some(Kind::Dir) {
            return Err(EPERM);
        }
    }
    for slot in SLOTS.iter() {
        if slot.used.load(Ordering::Relaxed) == 0 {
            slot.store_path(path);
            slot.kind.store(Kind::File as u8, Ordering::Relaxed);
            slot.len.store(0, Ordering::Relaxed);
            slot.used.store(1, Ordering::Relaxed);
            return find(path).ok_or(EINVAL);
        }
    }
    Err(EPERM) // volume full — bounded by MAX_FILES
}

/// Refuse a path that tries to leave its volume through a file slot.
pub fn check_parent(path: &[u8]) -> Result<(), i64> {
    validate_path(path)?;
    let mut i = 1usize;
    while i < path.len() {
        if path[i] == b'/' {
            let prefix = &path[..i];
            if prefix.len() > 1
                && let Some(slot) = find(prefix)
                && SLOTS[slot].kind() != Some(Kind::Dir)
            {
                return Err(EPERM);
            }
        }
        i += 1;
    }
    Ok(())
}

pub fn read(slot: usize, off: usize, out: &mut [u8]) -> usize {
    if slot < SLOTS.len() {
        SLOTS[slot].read(off, out)
    } else {
        0
    }
}

pub fn write(slot: usize, off: usize, src: &[u8]) -> usize {
    if slot < SLOTS.len() {
        SLOTS[slot].write(off, src)
    } else {
        0
    }
}

pub fn truncate(slot: usize) {
    if slot < SLOTS.len() {
        SLOTS[slot].truncate();
    }
}

pub fn size(slot: usize) -> usize {
    if slot < SLOTS.len() {
        SLOTS[slot].len.load(Ordering::Relaxed).min(FILE_CAP)
    } else {
        0
    }
}

pub fn kind(slot: usize) -> Option<Kind> {
    SLOTS.get(slot).and_then(Slot::kind)
}

/// Encode a `Stat` record into `out` (little-endian, fixed [`STAT_LEN`]).
/// Returns `false` when the caller's buffer is too small.
pub fn encode_stat(slot: usize, out: &mut [u8]) -> bool {
    if out.len() < STAT_LEN {
        return false;
    }
    let len = size(slot) as u64;
    for (i, b) in out[..8].iter_mut().enumerate() {
        *b = (len >> (8 * i)) as u8;
    }
    out[8] = match kind(slot) {
        Some(Kind::Dir) => Kind::Dir as u8,
        _ => Kind::File as u8,
    };
    out[9] = 0;
    for b in &mut out[10..STAT_LEN] {
        *b = 0;
    }
    true
}

/// Fill `out` with the direct children of an existing directory slot.
/// Each record is [`DIRENT_LEN`] bytes: `kind`, `name length`, then the
/// name (no trailing NUL). Returns the number of bytes written, always a
/// multiple of `DIRENT_LEN`, or `EINVAL` for a non-directory / bad path.
pub fn readdir(dir: usize, out: &mut [u8]) -> Result<usize, i64> {
    if kind(dir) != Some(Kind::Dir) {
        return Err(EINVAL);
    }
    let (prefix, plen) = SLOTS[dir].load_path();
    let prefix = &prefix[..plen];
    let cap = (out.len() / DIRENT_LEN).min(MAX_FILES);
    let mut used = 0usize;
    let mut emitted = [[0u8; MAX_NAME]; MAX_FILES];
    let mut emitted_len = [0usize; MAX_FILES];
    for (idx, slot) in SLOTS.iter().enumerate() {
        if idx == dir || slot.used.load(Ordering::Relaxed) == 0 {
            continue;
        }
        let (path, n) = slot.load_path();
        let path = &path[..n];
        let rest = if is_ancestor(prefix, path) {
            &path[prefix.len() + 1..]
        } else if prefix == b"/" && path.starts_with(b"/") && path[1..].iter().all(|b| *b != b'/') {
            &path[1..]
        } else {
            continue;
        };
        if rest.is_empty() || rest.len() > MAX_NAME || rest.contains(&b'/') {
            continue;
        }
        if emitted_len[..used]
            .iter()
            .any(|l| *l == rest.len() && emitted[..used].iter().any(|n| &n[..rest.len()] == rest))
        {
            continue;
        }
        if used >= cap {
            break;
        }
        emitted[used][..rest.len()].copy_from_slice(rest);
        emitted_len[used] = rest.len();
        let rec = &mut out[used * DIRENT_LEN..(used + 1) * DIRENT_LEN];
        rec[0] = match slot.kind() {
            Some(Kind::Dir) => Kind::Dir as u8,
            _ => Kind::File as u8,
        };
        rec[1] = rest.len() as u8;
        for b in &mut rec[2..] {
            *b = 0;
        }
        rec[2..2 + rest.len()].copy_from_slice(rest);
        used += 1;
    }
    Ok(used * DIRENT_LEN)
}
