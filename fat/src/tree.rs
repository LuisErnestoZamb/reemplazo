//! FS3: directories (`mkdir`) and long-file-name (LFN) writes — the
//! filesystem half of the full-tree checkout (`FS_TREE_OK`, then
//! `GIT_CHECKOUT_OK` in `cargo xtask smoke-install`).
//!
//! # What FS3 adds to FS2
//!
//! - [`Fat16::create_dir`] / [`Fat16::create_dir_all`]: allocate a
//!   cluster, initialise it with `.` (its own cluster) and `..` (the
//!   parent's first cluster, `0` when the parent is the fixed root),
//!   then write the directory entry in the parent. The fixed root never
//!   gets `.`/`..` (it has no cluster and the spec says so).
//! - [`Fat16::write_file_all`]: create missing parents, then write the
//!   file — the `mkdir -p $(dirname) && write` primitive the checkout
//!   uses.
//! - **LFN writes** for names that are not 8.3-representable: a unique
//!   uppercase 8.3 alias (`NAME~N.EXT`, numeric tail probed `1..=9999`)
//!   plus the UTF-16 long-name chain — 13 units per entry, sequence
//!   numbers descending with `0x40` on the physically first entry, the
//!   spec's rotate-right checksum over the alias, `0x0000` terminator
//!   then `0xFFFF` padding in the last entry, and all LFN entries
//!   written *before* the 8.3 entry they describe (the commit point).
//!
//! # Path discipline
//!
//! Every component is validated before a byte is written: the path must
//! be absolute, components may not be empty, `.` or `..` (no traversal,
//! so no escape), at most [`MAX_COMPONENTS`] components, and at most
//! [`MAX_PATH_BYTES`] bytes. A name that is *not* 8.3-encodable becomes
//! a long name only if it is representable: no `/ \ : * ? " < > |`, no
//! control characters, at most [`MAX_LFN_UNITS`] UTF-16 units
//! (surrogate pairs count twice, so non-BMP names are supported by the
//! same cap). Anything else is [`Error::InvalidName`] — refused, never
//! mangled. A long name whose alias space is exhausted (`~9999` taken)
//! is [`Error::NameConflict`].
//!
//! # Refusals leave the image byte-identical
//!
//! The free-slot run **and** the free cluster are found before any
//! mutation: no free cluster → [`Error::NoSpace`], no contiguous run of
//! `1 + LFN entries` slots → [`Error::NoSpace`], name collision →
//! [`Error::Exists`]. When every pre-check passes, the order is FAT →
//! directory cluster (zeroed, `.`, `..`) → parent entry last — the same
//! write-through, no-crash-consistency stance FS2 documents.
//!
//! Aliases never collide with an existing short name: the probe scans
//! the parent's raw entries (case-insensitively) and picks the first
//! free suffix. Reusing a deleted slot clears stale LFN entries in
//! front of it first, exactly like FS2's create path.

use super::dir::{DirLoc, MAX_LFN_UNITS, Placement, short_checksum};
use super::write::{EOC, Stamp, final_component, parse_83};
use super::{BlockDevice, Error, Fat16, read_bytes, write_bytes};

/// Directory attribute bit (FAT spec §7.2: `ATTR_DIRECTORY`).
const ATTR_DIRECTORY: u8 = 0x10;
/// Archive attribute (regular file, modified since last backup).
pub(crate) const ATTR_ARCHIVE: u8 = 0x20;
/// Long-name part marker (all four attribute bits set).
const ATTR_LFN: u8 = 0x0F;
/// Volume-label attribute (never a file, never an alias collision).
const ATTR_VOLUME: u8 = 0x08;
/// Highest numeric alias suffix probed (`~1`..`~9999`).
const MAX_ALIAS_PROBE: u32 = 9999;
/// Maximum path components walked by [`Fat16::create_dir_all`] /
/// [`Fat16::write_file_all`] (bounds the work a caller can demand).
const MAX_COMPONENTS: usize = 32;
/// Maximum absolute path length in bytes (allows 32 components of up to
/// 31 bytes, comfortably above the kernel's own 255-byte path cap).
const MAX_PATH_BYTES: usize = 1024;
/// Zero sector used to clear a freshly allocated directory cluster.
const ZERO_SECTOR: [u8; 512] = [0u8; 512];

/// A name to create: the 8.3 form that goes in the entry's 11 name
/// bytes, plus — for a long name — its UTF-16 units. `len == 0` means
/// the name was already 8.3-representable and no LFN chain is written.
#[derive(Clone, Copy)]
pub(crate) struct NamePlan {
    /// Space-padded, uppercase 8.3 name (the entry's `0..11`).
    pub(crate) short: [u8; 11],
    /// UTF-16 units of the long name (ignored when `len == 0`).
    units: [u16; MAX_LFN_UNITS],
    /// Valid prefix of `units`; `0` = plain 8.3 name.
    len: usize,
}

impl NamePlan {
    /// LFN directory entries this name needs (0 for a plain 8.3 name).
    pub(crate) fn lfn_entries(&self) -> u32 {
        if self.len == 0 {
            0
        } else {
            // `len` ≤ 255, so this cannot overflow.
            self.len.div_ceil(13) as u32
        }
    }
}

/// Folder a pair of characters makes an alias byte: uppercase ASCII
/// alphanumerics and FAT's legal punctuation pass, everything else is
/// dropped (the probe makes aliases unique, so dropping is safe).
fn alias_byte(c: char) -> Option<u8> {
    let b = if c.is_ascii() { c as u8 } else { return None };
    if b.is_ascii_alphanumeric()
        || matches!(
            b,
            b'$' | b'%'
                | b'\''
                | b'-'
                | b'_'
                | b'@'
                | b'~'
                | b'`'
                | b'!'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'^'
                | b'#'
                | b'&'
        )
    {
        Some(b.to_ascii_uppercase())
    } else {
        None
    }
}

/// Decimal digit count of an alias suffix (`1..=9999` → 1..=4).
fn digit_count(n: u32) -> usize {
    if n < 10 {
        1
    } else if n < 100 {
        2
    } else if n < 1000 {
        3
    } else {
        4
    }
}

/// Build the `n`-th 8.3 alias candidate for `name`: uppercase, illegal
/// characters dropped, base truncated to leave room for `~N`, the
/// extension truncated to three characters. The result is always a
/// legal 8.3 name (the free-suffix probe supplies uniqueness).
fn alias_candidate(name: &str, n: u32) -> [u8; 11] {
    // Windows-style split: the *last* dot starts the extension, except a
    // leading dot (".hidden") which belongs to the base.
    let (base_src, ext_src) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], name.get(i + 1..).unwrap_or("")),
        _ => (name, ""),
    };
    let digits = digit_count(n);
    // 8 = prefix + '~' + digits; `n ≤ 9999` keeps this ≥ 3.
    let room = 8usize.saturating_sub(1 + digits);
    let mut short = [b' '; 11];
    let mut w = 0usize;
    for c in base_src.chars() {
        if w >= room {
            break;
        }
        if let Some(b) = alias_byte(c) {
            short[w] = b;
            w += 1;
        }
    }
    if w == 0 {
        short[0] = b'_';
        w = 1;
    }
    short[w] = b'~';
    w += 1;
    // Digits, most significant first (`n` is at most 9999 → 4 bytes).
    let mut buf = [0u8; 4];
    let mut d = digits;
    let mut v = n;
    while d > 0 {
        d -= 1;
        buf[d] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    short[w..w + digits].copy_from_slice(&buf[..digits]);
    let mut e = 0usize;
    for c in ext_src.chars() {
        if e >= 3 {
            break;
        }
        if let Some(b) = alias_byte(c) {
            short[8 + e] = b;
            e += 1;
        }
    }
    short
}

/// Decode `name` into long-name UTF-16 units, rejecting everything a
/// long name may not contain and enforcing the 255-unit cap. A
/// non-BMP character contributes its surrogate pair (two units).
fn long_name_units(name: &str, out: &mut [u16; MAX_LFN_UNITS]) -> Result<usize, Error> {
    if name.is_empty() {
        return Err(Error::Path);
    }
    let mut n = 0usize;
    for c in name.chars() {
        if c.is_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            return Err(Error::InvalidName);
        }
        let cp = u32::from(c);
        let (hi, lo) = if cp > 0xFFFF {
            let rest = cp - 0x1_0000;
            (
                (0xD800 + (rest >> 10)) as u16,
                Some((0xDC00 + (rest & 0x3FF)) as u16),
            )
        } else {
            (cp as u16, None)
        };
        if n >= MAX_LFN_UNITS {
            return Err(Error::InvalidName);
        }
        out[n] = hi;
        n += 1;
        if let Some(lo) = lo {
            if n >= MAX_LFN_UNITS {
                return Err(Error::InvalidName);
            }
            out[n] = lo;
            n += 1;
        }
    }
    Ok(n)
}

/// One LFN directory entry for `plan`: sequence `seq` of `total`, 13
/// UTF-16 units (the tail padded with `0x0000` then `0xFFFF`), the
/// alias checksum, and the zero type/cluster fields FS1 validates.
fn lfn_entry(plan: &NamePlan, seq: u32, total: u32, checksum: u8) -> [u8; 32] {
    let mut raw = [0u8; 32];
    // `seq` ≤ 20, so the low five bits hold it; the physically first
    // entry (highest sequence) also carries the "last" flag.
    let mut order = seq as u8;
    if seq == total {
        order |= 0x40;
    }
    raw[0] = order;
    raw[11] = ATTR_LFN;
    // raw[12] type byte stays 0, raw[26..28] first-cluster stays 0.
    raw[13] = checksum;
    let base = (seq as usize - 1) * 13;
    for k in 0..13usize {
        let idx = base + k;
        let unit = if idx < plan.len {
            plan.units[idx]
        } else if idx == plan.len {
            0x0000 // name terminator
        } else {
            0xFFFF // padding after the terminator
        };
        let from = match k {
            0..=4 => 1 + k * 2,
            5..=10 => 14 + (k - 5) * 2,
            _ => 28 + (k - 11) * 2,
        };
        raw[from..from + 2].copy_from_slice(&unit.to_le_bytes());
    }
    raw
}

/// A 32-byte directory entry for `name`, attribute `attr`, first
/// cluster and size, with creation/access/write timestamps all set to
/// the caller's (no clock lives in this crate). FAT16's high cluster
/// word stays zero; a cluster that does not fit 16 bits is refused.
pub(crate) fn build_entry(
    name: &[u8; 11],
    attr: u8,
    cluster: u32,
    size: u32,
    date: u16,
    time: u16,
) -> Result<[u8; 32], Error> {
    let lo = u16::try_from(cluster).map_err(|_| Error::BadDirectory)?;
    let mut raw = [0u8; 32];
    raw[0..11].copy_from_slice(name);
    raw[11] = attr;
    raw[14..16].copy_from_slice(&time.to_le_bytes()); // creation time
    raw[16..18].copy_from_slice(&date.to_le_bytes()); // creation date
    raw[18..20].copy_from_slice(&date.to_le_bytes()); // last-access date
    raw[22..24].copy_from_slice(&time.to_le_bytes()); // write time
    raw[24..26].copy_from_slice(&date.to_le_bytes()); // write date
    raw[26..28].copy_from_slice(&lo.to_le_bytes()); // first cluster
    raw[28..32].copy_from_slice(&size.to_le_bytes()); // size
    Ok(raw)
}

/// Validate the shape of an absolute path *before* any mutation: at
/// most [`MAX_PATH_BYTES`], absolute, at most [`MAX_COMPONENTS`]
/// components, none empty, `.` or `..` (no traversal, so no escape out
/// of the volume). One trailing slash is allowed (a directory path);
/// anything else with an empty final component is refused.
fn validate_path(path: &str) -> Result<(), Error> {
    if path.len() > MAX_PATH_BYTES {
        return Err(Error::Path);
    }
    let body = path.strip_prefix('/').ok_or(Error::Path)?;
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return Err(Error::Path);
    }
    let mut components = 0usize;
    for component in body.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(Error::Path);
        }
        components += 1;
        if components > MAX_COMPONENTS {
            return Err(Error::Path);
        }
    }
    Ok(())
}

impl<'a, D: BlockDevice + ?Sized> Fat16<'a, D> {
    /// Create directory `path`; its parent must exist and the name must
    /// be free ([`Error::Exists`] otherwise, file or directory). One
    /// trailing slash is accepted (it names a directory anyway).
    pub fn create_dir(&self, path: &str, stamp: Stamp) -> Result<(), Error> {
        validate_path(path)?;
        let path = path.strip_suffix('/').unwrap_or(path);
        match self.locate(path)? {
            Placement::Found { .. } => Err(Error::Exists),
            Placement::Missing { parent } => {
                self.create_dir_in(parent, final_component(path), stamp)?;
                Ok(())
            }
        }
    }

    /// Create `path` and every missing parent (`mkdir -p`). An existing
    /// directory is success ([`Ok`]); an existing *file* in the path is
    /// [`Error::NotAFile`]. The whole path is validated (components,
    /// length, no `.`/`..`) before the first byte is written, so a
    /// refused traversal never leaves half a tree behind.
    pub fn create_dir_all(&self, path: &str, stamp: Stamp) -> Result<(), Error> {
        validate_path(path)?;
        let body = path.strip_prefix('/').ok_or(Error::Path)?;
        let mut loc = DirLoc::Root;
        let mut rest = body;
        loop {
            if rest.is_empty() {
                return Ok(()); // trailing slash: the directory exists
            }
            let (component, tail) = match rest.find('/') {
                Some(i) => (&rest[..i], rest.get(i + 1..).unwrap_or("")),
                None => (rest, ""),
            };
            match self.scan_dir(loc, component)? {
                Some((_, _, entry)) => {
                    if !entry.is_dir() {
                        return Err(Error::NotAFile);
                    }
                    if tail.is_empty() {
                        return Ok(());
                    }
                    if entry.first_cluster < 2 {
                        return Err(Error::BadDirectory);
                    }
                    loc = DirLoc::Cluster(entry.first_cluster);
                }
                None => {
                    loc = self.create_dir_in(loc, component, stamp)?;
                    if tail.is_empty() {
                        return Ok(());
                    }
                }
            }
            rest = tail;
        }
    }

    /// Create the file at `path`, creating any missing parent directories
    /// first (the checkout's write primitive). Existing files are
    /// overwritten through [`Fat16::write_file`]'s semantics. The whole
    /// path is validated before any directory is created.
    pub fn write_file_all(&self, path: &str, data: &[u8], stamp: Stamp) -> Result<(), Error> {
        validate_path(path)?;
        self.create_parents(path, stamp)?;
        self.write_file(path, data, stamp)
    }

    /// Create the parent directories of `path` (the part before the
    /// last `/`); `/x` and `x` fail the earlier absolute-path check.
    fn create_parents(&self, path: &str, stamp: Stamp) -> Result<(), Error> {
        if path.len() > MAX_PATH_BYTES {
            return Err(Error::Path);
        }
        let body = path.strip_prefix('/').ok_or(Error::Path)?;
        if body.is_empty() {
            return Err(Error::Path);
        }
        match body.rfind('/') {
            None | Some(0) => Ok(()), // the parent is the fixed root
            // `body` starts one byte into `path`, so the parent ends at
            // `i + 1` in `path` (and a trailing slash was validated).
            Some(i) => self.create_dir_all(path.get(..i + 1).ok_or(Error::Path)?, stamp),
        }
    }

    /// Plan the name `name` inside `dir`: a plain 8.3 name when the
    /// component is 8.3-encodable, otherwise a long name with the first
    /// free `~N` alias. Repeatedly reading the directory is what makes
    /// the alias unique; [`Error::NameConflict`] when `~9999` is taken
    /// (a directory that full would hit [`Error::NoSpace`] first on any
    /// volume this crate formats, so the variant is a guard for
    /// unusually large directories).
    pub(crate) fn plan_name(&self, dir: DirLoc, name: &str) -> Result<NamePlan, Error> {
        if let Ok(short) = parse_83(name) {
            return Ok(NamePlan {
                short,
                units: [0; MAX_LFN_UNITS],
                len: 0,
            });
        }
        let mut units = [0u16; MAX_LFN_UNITS];
        let len = long_name_units(name, &mut units)?;
        for n in 1..=MAX_ALIAS_PROBE {
            let short = alias_candidate(name, n);
            if !self.short_in_use(dir, &short)? {
                return Ok(NamePlan { short, units, len });
            }
        }
        Err(Error::NameConflict)
    }

    /// Does any live 8.3 entry in `dir` already carry `want`? Scans the
    /// raw slots (case-insensitively), skipping LFN parts, deleted slots
    /// and volume labels; stops at the `0x00` end marker.
    fn short_in_use(&self, dir: DirLoc, want: &[u8; 11]) -> Result<bool, Error> {
        let total = self.dir_slots(dir)?;
        for idx in 0..total {
            let mut raw = [0u8; 32];
            read_bytes(self.dev, self.logical_byte(dir, idx)?, &mut raw)?;
            match raw[0] {
                0x00 => return Ok(false),
                0xE5 => continue,
                _ => {}
            }
            if raw[11] == ATTR_LFN || raw[11] & ATTR_VOLUME != 0 {
                continue;
            }
            if raw[..11]
                .iter()
                .zip(want.iter())
                .all(|(&r, &w)| r.to_ascii_uppercase() == w)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Number of directory slots in `dir`'s existing extent: the fixed
    /// root's entry count, or every slot of every cluster in a
    /// subdirectory's chain (cycle-checked by [`Fat16::walk_chain`]).
    /// A subdirectory grows through
    /// [`alloc_run_or_grow`](Self::alloc_run_or_grow) when its extent
    /// has no free run; the fixed root cannot grow (FAT specification).
    pub(crate) fn dir_slots(&self, dir: DirLoc) -> Result<u32, Error> {
        match dir {
            DirLoc::Root => Ok(self.root_entries),
            DirLoc::Cluster(head) => {
                let per = self.cluster_bytes / 32; // ≥ 16: clusters are ≥ 512 B
                if head < 2 || per == 0 {
                    return Err(Error::BadDirectory);
                }
                let (count, _) = self.walk_chain(head)?;
                count.checked_mul(per).ok_or(Error::BadDirectory)
            }
        }
    }

    /// Translate a logical slot index inside `dir` into the concrete
    /// directory location a write targets (root index, or cluster +
    /// slot). Index bounds come from [`dir_slots`](Self::dir_slots).
    pub(crate) fn logical_slot(&self, dir: DirLoc, idx: u32) -> Result<(DirLoc, u32), Error> {
        match dir {
            DirLoc::Root => {
                if idx >= self.root_entries {
                    return Err(Error::BadDirectory);
                }
                Ok((DirLoc::Root, idx))
            }
            DirLoc::Cluster(head) => {
                let per = self.cluster_bytes / 32;
                if head < 2 || per == 0 {
                    return Err(Error::BadDirectory);
                }
                let (cluster, _) = self.chain_nth(head, idx / per + 1)?;
                Ok((DirLoc::Cluster(cluster), idx % per))
            }
        }
    }

    /// Byte offset of logical slot `idx` inside `dir`.
    pub(crate) fn logical_byte(&self, dir: DirLoc, idx: u32) -> Result<u64, Error> {
        let (loc, slot) = self.logical_slot(dir, idx)?;
        self.slot_byte(loc, slot)
    }

    /// Find the first run of `count` free (deleted `0xE5` or unused
    /// `0x00`) slots in `dir`'s existing extent and return its logical
    /// start index. A `0x00` slot ends the directory: everything from
    /// there to the end of the extent is free. Read-only, so a refusal
    /// ([`None`] → [`Error::NoSpace`] at the caller) never mutates.
    pub(crate) fn alloc_run(&self, dir: DirLoc, count: u32) -> Result<Option<u32>, Error> {
        if count == 0 {
            return Err(Error::NoSpace);
        }
        let total = self.dir_slots(dir)?;
        let mut run_start = 0u32;
        let mut free = 0u32;
        for idx in 0..total {
            let mut raw = [0u8; 32];
            read_bytes(self.dev, self.logical_byte(dir, idx)?, &mut raw)?;
            match raw[0] {
                0x00 => {
                    // End of directory: `run_start..total` is all free.
                    return Ok(if total - run_start >= count {
                        Some(run_start)
                    } else {
                        None
                    });
                }
                0xE5 => {
                    free += 1;
                    if free >= count {
                        return Ok(Some(run_start));
                    }
                }
                _ => {
                    free = 0;
                    run_start = idx + 1;
                }
            }
        }
        Ok(None)
    }

    /// [`alloc_run`](Self::alloc_run), growing a **subdirectory** by one
    /// cluster when its current extent has no run long enough. The root
    /// directory is fixed by the FAT specification and cannot grow
    /// ([`Error::NoSpace`]).
    ///
    /// This lifts FS3's documented "directories are never grown" limit,
    /// which a real workload needs: git's `.git/objects` fan-out creates
    /// up to 256 two-hex subdirectories, and a 4 KiB cluster holds only
    /// 128 slots. Growth zeroes the new cluster (every slot reads as the
    /// `0x00` end marker), marks it end-of-chain, and only then links it
    /// from the old tail — an interrupted growth leaks one free cluster
    /// instead of corrupting a chain (FAT-first discipline, same as the
    /// writer's other ordering decisions).
    pub(crate) fn alloc_run_or_grow(&self, dir: DirLoc, count: u32) -> Result<u32, Error> {
        if let Some(run) = self.alloc_run(dir, count)? {
            return Ok(run);
        }
        self.grow_dir(dir)?;
        self.alloc_run(dir, count)?.ok_or(Error::NoSpace)
    }

    /// Append one zeroed cluster to the directory `dir`'s chain.
    fn grow_dir(&self, dir: DirLoc) -> Result<(), Error> {
        let DirLoc::Cluster(head) = dir else {
            return Err(Error::NoSpace); // the fixed root cannot grow
        };
        let (count, tail) = self.walk_chain(head)?;
        if count == 0 {
            return Err(Error::BadDirectory);
        }
        if count >= self.clusters {
            return Err(Error::NoSpace);
        }
        let fresh = self.alloc_free()?;
        let fresh_entry = u16::try_from(fresh).map_err(|_| Error::NoSpace)?;
        if !self.cluster_bytes.is_multiple_of(512) {
            return Err(Error::BadDirectory); // mount invariant
        }
        let base = self.cluster_byte(fresh)?;
        let zeros = [0u8; 512];
        for chunk in 0..self.cluster_bytes / 512 {
            let offset = base
                .checked_add(u64::from(chunk) * 512)
                .ok_or(Error::OutOfRange)?;
            write_bytes(self.dev, offset, &zeros)?;
        }
        self.fat_set(fresh, EOC)?;
        self.fat_set(tail, fresh_entry)?;
        Ok(())
    }

    /// Write the name (LFN chain when needed, then the 8.3 entry that
    /// seals it) into the slot run at `run`. The 8.3 entry is written
    /// last: it is the commit point readers consult. Stale LFN parts in
    /// front of the run are cleared first so a reused slot can never
    /// inherit an old long name.
    #[allow(clippy::too_many_arguments)] // one 32-byte record's worth of fields
    pub(crate) fn install_entry(
        &self,
        dir: DirLoc,
        run: u32,
        plan: &NamePlan,
        attr: u8,
        cluster: u32,
        size: u32,
        date: u16,
        time: u16,
    ) -> Result<(), Error> {
        let entries = plan.lfn_entries();
        let (clear_loc, clear_slot) = self.logical_slot(dir, run)?;
        self.clear_stale_lfn(clear_loc, clear_slot)?;
        if entries > 0 {
            let checksum = short_checksum(&plan.short);
            for seq in (1..=entries).rev() {
                let raw = lfn_entry(plan, seq, entries, checksum);
                let idx = run + (entries - seq);
                write_bytes(self.dev, self.logical_byte(dir, idx)?, &raw)?;
            }
        }
        let (loc, slot) = self.logical_slot(dir, run + entries)?;
        self.create_entry(loc, slot, &plan.short, attr, cluster, size, date, time)
    }

    /// Create one directory inside an existing directory `parent` and
    /// return its location. Pre-checks (name plan, alias probe, slot
    /// run, free cluster) all run before any mutation.
    fn create_dir_in(&self, parent: DirLoc, name: &str, stamp: Stamp) -> Result<DirLoc, Error> {
        if name.is_empty() || name == "." || name == ".." {
            return Err(Error::Path);
        }
        let plan = self.plan_name(parent, name)?;
        let (date, time) = stamp.encode()?;
        let entries = plan.lfn_entries();
        let run = self.alloc_run_or_grow(parent, entries + 1)?;
        // The directory's own cluster, linked end-of-chain (FAT first).
        let cluster = self.alloc_free()?;
        self.fat_set(cluster, EOC)?;
        // The directory's contents: zeroed cluster, then `.` and `..`.
        let parent_head = match parent {
            DirLoc::Root => 0,
            DirLoc::Cluster(head) => head,
        };
        self.init_dir_cluster(cluster, parent_head, date, time)?;
        // The parent's entry (with its LFN chain) is the commit point.
        self.install_entry(parent, run, &plan, ATTR_DIRECTORY, cluster, 0, date, time)?;
        Ok(DirLoc::Cluster(cluster))
    }

    /// Write a fresh directory cluster: zero every byte (it may have
    /// held an old file's data), then `.` (own cluster) and `..`
    /// (`parent`, `0` for the root) with the directory attribute and a
    /// zero size.
    fn init_dir_cluster(
        &self,
        cluster: u32,
        parent: u32,
        date: u16,
        time: u16,
    ) -> Result<(), Error> {
        let base = self.cluster_byte(cluster)?;
        let mut off = 0u64;
        while off < u64::from(self.cluster_bytes) {
            write_bytes(self.dev, base + off, &ZERO_SECTOR)?;
            off += 512;
        }
        let dot = build_entry(b".          ", ATTR_DIRECTORY, cluster, 0, date, time)?;
        write_bytes(self.dev, base, &dot)?;
        let dotdot = build_entry(b"..         ", ATTR_DIRECTORY, parent, 0, date, time)?;
        write_bytes(self.dev, base + 32, &dotdot)?;
        Ok(())
    }
}

// `write` imports [`ATTR_ARCHIVE`] and [`build_entry`] from here; `Stamp`
// and `EOC` stay defined there (FS2) and are reused by the directory
// writer so both halves spell the transfer type once.
