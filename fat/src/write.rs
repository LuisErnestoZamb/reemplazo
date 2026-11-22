//! FAT16 write support — the FS2 slice (`FS_WRITE_OK`, `cargo xtask
//! smoke-install`), extended by FS3's directory/long-name writer
//! ([`crate::tree`], `FS_TREE_OK`).
//!
//! The minimal honest write set on top of FS1's reader: create a file,
//! overwrite in place, grow the cluster chain, truncate and free the
//! tail. Every refusal fail-closes with an [`Error`]; nothing here
//! panics on disk data.
//!
//! # Naming rule
//!
//! FS2 required the final path component to be **8.3-encodable** and
//! refused everything else. FS3 keeps that fast path and adds the long
//! path: a name that is not 8.3-encodable gets a generated unique 8.3
//! alias plus an LFN chain ([`crate::tree`]'s module docs carry the
//! alias probe and the exact entry bytes). 8.3 names are uppercase
//! (lookup stays ASCII-case-insensitive, so `read_file("/lower.txt")`
//! finds `LOWER.TXT`). A long name containing a FAT-illegal character
//! (`/\:*?"<>|`, control bytes, > 255 UTF-16 units) is
//! [`Error::InvalidName`] — refused rather than mangled. Overwriting an
//! *existing* file keeps its stored names byte-for-byte and only
//! changes size/cluster/timestamps.
//!
//! # Ordering and crash consistency
//!
//! **Write-through, no `flush()`.** Every FAT sector (both copies),
//! data sector and directory sector is written to the device inside the
//! operation — there is no cache in this crate or in the kernel's ATA
//! adapter. The order within one operation is fixed:
//!
//! 1. **FAT first** — allocate/link or cut/free the cluster chain, so
//!    the chain a reader walks is never shorter than what comes next;
//! 2. **data** — the file's bytes into the (now-complete) chain;
//! 3. **directory entry last** — size, head cluster and timestamps.
//!    The directory entry is the single field readers consult to know
//!    a file's extent, so writing it last makes it the operation's
//!    commit point.
//!
//! **Crash consistency is explicitly NOT a goal of FS2.** There is no
//! journal, no flush barrier, and the drive-side `FLUSH CACHE` (0xE7)
//! command is not issued — a power cut mid-operation can leave a
//! partially updated volume. Power-loss ordering is a later milestone;
//! the FS2 proof is a same-boot re-mount read-back, not a power-cycle
//! test.
//!
//! # Refusals (fail-closed, no panics)
//!
//! - disk full / directory full → [`Error::NoSpace`] (checked *before*
//!   any mutation: needed clusters vs. volume capacity, free slot vs.
//!   directory extent);
//! - size beyond FAT16/LBA28 reach → the same capacity checks over
//!   checked arithmetic (the writer's capacity pre-check, `u32`
//!   conversions), plus
//!   the device's own LBA28 range check underneath;
//! - corrupt chain mid-write → [`Error::BadChain`], reusing FS1's
//!   validators (cycle hop-budget, out-of-range cluster,
//!   free/reserved/bad entry inside a chain) — walked **before** any
//!   mutation, so a refused write leaves the volume untouched;
//! - a device without write support → [`Error::ReadOnly`] (the
//!   [`BlockDevice::write_at`] default);
//! - a timestamp outside FAT's range → [`Error::Stamp`];
//! - a path that is a directory → [`Error::NotAFile`]; a missing parent
//!   directory → [`Error::NotFound`] (use
//!   [`Fat16::create_dir_all`](crate::Fat16::create_dir_all) /
//!   [`Fat16::write_file_all`](crate::Fat16::write_file_all) to create
//!   parents); `create_file` on an existing path → [`Error::Exists`].
//!
//! # Documented limits
//!
//! - **No handles.** The API is stateless (path-based), so the
//!   "read-only handle / removed file" refusals of a handle API do not
//!   exist here; the closest analogues are [`Error::Exists`] (refusing
//!   to clobber via `create_file`) and [`Error::NotAFile`].
//! - **Creation works in the root and in existing subdirectories**;
//!   directories are created with [`crate::tree`]'s `create_dir`/
//!   `create_dir_all` (FS3) and a full subdirectory grows by one
//!   zeroed cluster on demand (the FS4 extension
//!   [`crate::tree`]'s `alloc_run_or_grow` provides — git's
//!   `.git/objects` fan-out needs it). The fixed root directory cannot
//!   grow (`NoSpace` when full, per the FAT specification).
//! - **No delete/unlink** — freeing happens only inside truncate of the
//!   file being written (tail or whole chain), never on another file's
//!   chain, so no double-free is reachable through this API.
//! - **Pre-existing cross-links are not detected**: proving that two
//!   *different* files share a cluster needs a visited-set (a heap
//!   allocation this `no_std`, no-`alloc` crate deliberately avoids).
//!   The writer never *creates* a cross-link (it only allocates entries
//!   that read as free) and the FS1 validators catch cycles,
//!   out-of-range hops and free/bad entries mid-write; the read-back
//!   proof and the hostile tests cover those. Detecting cross-file
//!   sharing is deferred with the heap.

use super::dir::{DirLoc, Placement};
use super::tree::build_entry;
use super::{BlockDevice, Error, Fat16, Next, classify, read_bytes, write_bytes};

/// End-of-chain marker written into a FAT16 entry (any value in
/// `0xFFF8..=0xFFFF` terminates a chain; the canonical all-ones form is
/// what formatters write).
pub(crate) const EOC: u16 = 0xFFFF;

/// Maximum LFN entries a chain may hold (FAT spec §7.4) — the bound on
/// the stale-LFN backwalk when a create reuses a deleted slot.
const MAX_LFN_ENTRIES: u32 = 20;

/// A caller-supplied timestamp for a written file. This crate has **no
/// clock**: the kernel passes its CMOS RTC reading, tests pass a fixed
/// value, and a caller with no clock passes [`Stamp::FAT_EPOCH`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// Full year, 1980..=2107 (FAT's representable range).
    pub year: u16,
    /// 1..=12.
    pub month: u8,
    /// 1..=31, valid for `month`/`year`.
    pub day: u8,
    /// 0..=23.
    pub hour: u8,
    /// 0..=59.
    pub minute: u8,
    /// 0..=59.
    pub second: u8,
}

impl Stamp {
    /// The documented fixed fallback for "no clock": FAT's epoch,
    /// 1980-01-01 00:00:00.
    pub const FAT_EPOCH: Self = Self {
        year: 1980,
        month: 1,
        day: 1,
        hour: 0,
        minute: 0,
        second: 0,
    };

    /// Pack into FAT's date and time words, refusing anything outside
    /// the representable range ([`Error::Stamp`]) — no clamping, no
    /// guessing (fail-closed, like every other refusal here).
    pub(crate) fn encode(&self) -> Result<(u16, u16), Error> {
        if !(1980..=2107).contains(&self.year)
            || !(1..=12).contains(&self.month)
            || self.day < 1
            || self.day > days_in_month(self.year, self.month)
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(Error::Stamp);
        }
        // Checked above: year - 1980 ∈ 0..=127, so the packed words
        // fit u16 (date: 15 bits used, time: 16 with second/2).
        let date = ((self.year - 1980) << 9) | (u16::from(self.month) << 5) | u16::from(self.day);
        let time = (u16::from(self.hour) << 11)
            | (u16::from(self.minute) << 5)
            | (u16::from(self.second) / 2);
        Ok((date, time))
    }
}

/// Days in `month` of `year` (0 for an invalid month — the caller
/// range-checks `month` first, this only supplies February's leap rule).
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Is `c` legal in an 8.3 component (FAT spec's character set)?
fn name_char_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
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
}

/// Encode the final path component as a space-padded 11-byte 8.3 name,
/// folding ASCII lowercase to uppercase. Refuses (see the module docs'
/// naming rule, and [`crate::tree`] for the long-name path): an empty
/// name ([`Error::Path`]), an empty base or base > 8 / extension > 3 / a
/// second dot / any character outside the legal set
/// ([`Error::InvalidName`]).
pub(crate) fn parse_83(name: &str) -> Result<[u8; 11], Error> {
    if name.is_empty() {
        return Err(Error::Path);
    }
    let bytes = name.as_bytes();
    let (base, ext) = match bytes.iter().position(|&b| b == b'.') {
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
        None => (bytes, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err(Error::InvalidName);
    }
    if ext.contains(&b'.') {
        return Err(Error::InvalidName); // "A.B.C": two separators
    }
    let mut out = [b' '; 11];
    for (slot, &c) in out.iter_mut().zip(base) {
        if !name_char_ok(c) {
            return Err(Error::InvalidName);
        }
        *slot = c.to_ascii_uppercase();
    }
    for (slot, &c) in out[8..].iter_mut().zip(ext) {
        if !name_char_ok(c) {
            return Err(Error::InvalidName);
        }
        *slot = c.to_ascii_uppercase();
    }
    Ok(out)
}

/// The final component of an absolute path (`locate` has already
/// validated the path shape; a path of `/` yields the empty string,
/// which [`parse_83`] refuses). `rsplit` yields at least one item for
/// any `&str`, so the default is unreachable — `unwrap_or_default`
/// keeps it panic-free anyway.
pub(crate) fn final_component(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or_default()
}

impl<'a, D: BlockDevice + ?Sized> Fat16<'a, D> {
    /// Create the file at `path` with contents `data`, or overwrite it
    /// if it already exists (the general create-or-overwrite primitive
    /// the boot proof and the tests use).
    ///
    /// Semantics by existing state: absent → create (an 8.3 name, or a
    /// long name behind an LFN chain — see [`crate::tree`]); present and
    /// shorter → truncate + free the tail;
    /// present and longer → grow the chain; present and equal → in-place
    /// overwrite. Directories are refused ([`Error::NotAFile`]).
    /// `stamp` records the write (and creation) time — no clock lives
    /// in this crate.
    pub fn write_file(&self, path: &str, data: &[u8], stamp: Stamp) -> Result<(), Error> {
        self.write_impl(path, data, stamp, true)
    }

    /// Create the file at `path` with contents `data`, refusing if it
    /// already exists ([`Error::Exists`]) — the no-clobber variant of
    /// [`write_file`](Self::write_file).
    pub fn create_file(&self, path: &str, data: &[u8], stamp: Stamp) -> Result<(), Error> {
        self.write_impl(path, data, stamp, false)
    }

    /// The one write implementation; `allow_overwrite` selects between
    /// [`write_file`](Self::write_file) and
    /// [`create_file`](Self::create_file).
    ///
    /// Order of work (rationale in the module docs): validate everything
    /// *before* mutating (path, name, capacity, free slot, existing
    /// chain), then FAT → data → directory entry.
    fn write_impl(
        &self,
        path: &str,
        data: &[u8],
        stamp: Stamp,
        allow_overwrite: bool,
    ) -> Result<(), Error> {
        let placement = self.locate(path)?;

        // Where the entry lives (or will live) and its current state.
        // Overwrite keeps the stored 8.3 name byte-for-byte (also the
        // case when the path matched via an LFN); a create plans the
        // name — 8.3, or a long name with its unique alias (FS3).
        let create = match &placement {
            Placement::Found { entry, .. } => {
                if !allow_overwrite {
                    return Err(Error::Exists);
                }
                if entry.is_dir() {
                    return Err(Error::NotAFile);
                }
                None
            }
            Placement::Missing { parent } => {
                let plan = self.plan_name(*parent, final_component(path))?;
                Some((*parent, plan))
            }
        };
        let (date, time) = stamp.encode()?;

        // Capacity pre-checks — before anything is written.
        let needed = self.clusters_needed(data.len())?;
        let data_len = u32::try_from(data.len()).map_err(|_| Error::OutOfRange)?;

        // Directory-slot pre-check for a create: refuse before touching
        // the FAT if the directory has no run long enough for the LFN
        // chain plus the 8.3 entry.
        let create_slot = match &create {
            Some((parent, plan)) => {
                let slots = plan.lfn_entries() + 1;
                Some((*parent, self.alloc_run_or_grow(*parent, slots)?))
            }
            None => None,
        };

        // Existing chain, walked with FS1's validators *before* any
        // mutation: a cycle or out-of-range hop refuses the write and
        // leaves the volume untouched.
        let (mut head, have, tail) = match &placement {
            Placement::Found { entry, .. } => {
                let (count, tail) = self.walk_chain(entry.first_cluster)?;
                (entry.first_cluster, count, tail)
            }
            Placement::Missing { .. } => (0, 0, 0),
        };

        // Phase 1: FAT — grow or shrink the chain to exactly `needed`.
        if needed > have {
            let mut prev = if have > 0 { Some(tail) } else { None };
            let mut added = 0u32;
            while added < needed - have {
                let cluster = self.alloc_free()?;
                // FAT16 entries hold 16-bit cluster numbers; the mount
                // window (≤ 65524 clusters) keeps this conversion lossless.
                let link = u16::try_from(cluster).map_err(|_| Error::BadChain)?;
                match prev {
                    Some(p) => self.fat_set(p, link)?,
                    None => head = cluster,
                }
                self.fat_set(cluster, EOC)?;
                prev = Some(cluster);
                added += 1;
            }
        } else if needed < have {
            if needed == 0 {
                self.free_from(head)?;
                head = 0;
            } else {
                let (cut, next) = self.chain_nth(head, needed)?;
                if let Some(next) = next {
                    self.free_from(next)?;
                }
                self.fat_set(cut, EOC)?;
            }
        }

        // Phase 2: data into the (now exactly `needed`-long) chain.
        if !data.is_empty() {
            self.write_chain(head, data)?;
        }

        // Phase 3: directory entry — the commit point, written last.
        match (&placement, &create_slot) {
            (Placement::Found { loc, slot, .. }, _) => {
                self.update_entry(*loc, *slot, head, data_len, date, time)?;
            }
            (Placement::Missing { .. }, Some((dir, run))) => {
                let (_, plan) = create.as_ref().ok_or(Error::Path)?;
                self.install_entry(
                    *dir,
                    *run,
                    plan,
                    super::tree::ATTR_ARCHIVE,
                    head,
                    data_len,
                    date,
                    time,
                )?;
            }
            // Unreachable: `create_slot` was pre-checked above. Kept as
            // a fail-closed arm rather than an unwrap.
            (Placement::Missing { .. }, None) => return Err(Error::NoSpace),
        }
        Ok(())
    }

    /// Clusters `data.len()` bytes occupy, refusing
    /// [`Error::NoSpace`] when the volume cannot hold them — the
    /// capacity refusal, checked before any mutation (every step is
    /// checked arithmetic: `usize → u64` widening, `div_ceil`, compare
    /// against the mount-validated cluster count).
    fn clusters_needed(&self, len: usize) -> Result<u32, Error> {
        if len == 0 {
            return Ok(0);
        }
        let needed = (len as u64).div_ceil(u64::from(self.cluster_bytes));
        if needed > u64::from(self.clusters) {
            return Err(Error::NoSpace);
        }
        u32::try_from(needed).map_err(|_| Error::NoSpace)
    }

    /// Walk the chain from `head` to its explicit end-of-chain marker:
    /// returns `(cluster_count, tail_cluster)`; `(0, 0)` for an empty
    /// file (`head == 0`). Reuses FS1's validators — range check per
    /// hop (the range check in `cluster_byte`), [`classify`]
    /// (free/reserved/bad entry inside a chain is [`Error::BadChain`],
    /// not a silent stop) and
    /// the hop budget that turns a cyclic FAT into [`Error::BadChain`]
    /// instead of a hang.
    pub(crate) fn walk_chain(&self, head: u32) -> Result<(u32, u32), Error> {
        if head == 0 {
            return Ok((0, 0));
        }
        let mut cluster = head;
        let mut count = 0u32;
        loop {
            self.cluster_byte(cluster)?; // range-check this hop
            count += 1;
            if count > self.clusters {
                return Err(Error::BadChain); // cycle: more hops than the volume has
            }
            match classify(self.fat_entry(cluster)?)? {
                Next::Eoc => return Ok((count, cluster)),
                Next::Data(next) => cluster = next,
            }
        }
    }

    /// The `n`-th cluster of the chain (1-based) and its successor, for
    /// truncation and for logical directory-slot addressing. `n ≤ have`
    /// is guaranteed by the caller's earlier
    /// [`walk_chain`](Self::walk_chain), so a chain that ends early here
    /// means the disk changed under us → [`Error::BadChain`].
    pub(crate) fn chain_nth(&self, head: u32, n: u32) -> Result<(u32, Option<u32>), Error> {
        let mut cluster = head;
        for _ in 1..n {
            // `n ≤ clusters` (see above), so this loop is bounded by
            // the volume size even without an extra hop counter.
            match classify(self.fat_entry(cluster)?)? {
                Next::Eoc => return Err(Error::BadChain),
                Next::Data(next) => {
                    self.cluster_byte(next)?;
                    cluster = next;
                }
            }
        }
        let next = match classify(self.fat_entry(cluster)?)? {
            Next::Eoc => None,
            Next::Data(next) => {
                self.cluster_byte(next)?;
                Some(next)
            }
        };
        Ok((cluster, next))
    }

    /// Free every cluster from `start` to the end of its chain (used
    /// only on the *target file's own* chain during truncate — this API
    /// has no unlink, so another file's chain is never touched).
    ///
    /// Each entry is read before it is zeroed, the hop budget bounds
    /// the walk, and a cluster visited twice shows up as free
    /// ([`classify`] rejects `0x0000`) → [`Error::BadChain`] instead of
    /// a double-free. If the walk fails midway some tail clusters are
    /// already free — a partial state, acceptable only because crash
    /// consistency is explicitly not a goal (module docs).
    fn free_from(&self, start: u32) -> Result<(), Error> {
        let mut cluster = start;
        let mut visited = 0u32;
        loop {
            visited += 1;
            if visited > self.clusters {
                return Err(Error::BadChain);
            }
            let raw = self.fat_entry(cluster)?;
            match classify(raw)? {
                Next::Eoc => {
                    self.fat_set(cluster, 0)?;
                    return Ok(());
                }
                Next::Data(next) => {
                    self.cluster_byte(next)?; // range-check before following
                    self.fat_set(cluster, 0)?;
                    cluster = next;
                }
            }
        }
    }

    /// First free (`0x0000`) FAT entry in the data region — the
    /// allocator. It starts from the mount's allocation hint (the last
    /// search position), which turns a sequential checkout into a linear
    /// scan instead of an O(n²) one, and wraps to `2..hint` when the
    /// tail is exhausted so a cluster freed behind the hint is still
    /// reused. Every candidate is re-verified against the FAT, so the
    /// hint can never hand out an in-use cluster (no cross-links) and
    /// [`Error::NoSpace`] means a full volume scan found nothing.
    pub(crate) fn alloc_free(&self) -> Result<u32, Error> {
        let hint = self.next_free.get().clamp(2, self.clusters + 1);
        if let Some(cluster) = self.first_free_from(hint)? {
            self.next_free.set(cluster);
            return Ok(cluster);
        }
        if hint > 2 {
            // The tail is full: a truncate may have freed something
            // behind the hint. Any hit here is necessarily `< hint`
            // (the tail scan above found nothing at or above it).
            if let Some(cluster) = self.first_free_from(2)?
                && cluster < hint
            {
                self.next_free.set(cluster);
                return Ok(cluster);
            }
        }
        Err(Error::NoSpace)
    }

    /// First free FAT entry in `start..=clusters + 1`, or `None`.
    fn first_free_from(&self, start: u32) -> Result<Option<u32>, Error> {
        for cluster in start..=self.clusters + 1 {
            if self.fat_entry(cluster)? == 0 {
                return Ok(Some(cluster));
            }
        }
        Ok(None)
    }

    /// Set FAT entry `cluster` in **every** FAT copy (spec: the copies
    /// are mirrors; a formatter writes both, and so does every write
    /// here — the mirror test pins it). Refuses any cluster outside the
    /// data region — reserved entries 0/1 are never writable.
    pub(crate) fn fat_set(&self, cluster: u32, value: u16) -> Result<(), Error> {
        if cluster < 2 || cluster > self.clusters + 1 {
            return Err(Error::BadChain);
        }
        let base = u64::from(self.fat_start) * u64::from(self.bps) + u64::from(cluster) * 2;
        let bytes = value.to_le_bytes();
        for copy in 0..self.fat_count {
            let offset = base
                + u64::from(copy)
                    .checked_mul(u64::from(self.fat_sectors) * u64::from(self.bps))
                    .ok_or(Error::OutOfRange)?;
            write_bytes(self.dev, offset, &bytes)?;
        }
        Ok(())
    }

    /// Copy `data` into the clusters of `head`'s chain. The chain must
    /// already be exactly long enough (the caller grew or trimmed it),
    /// so a chain ending before the data does is an internal
    /// inconsistency → [`Error::BadChain`], never a partial silent
    /// write. Each hop is range- and classify-checked, cycle-bounded.
    fn write_chain(&self, head: u32, data: &[u8]) -> Result<(), Error> {
        let cluster_bytes = self.cluster_bytes as usize;
        let mut done = 0usize;
        let mut cluster = head;
        let mut visited = 0u32;
        while done < data.len() {
            if cluster < 2 {
                return Err(Error::BadChain);
            }
            let byte = self.cluster_byte(cluster)?;
            let n = core::cmp::min(cluster_bytes, data.len() - done);
            write_bytes(self.dev, byte, &data[done..done + n])?;
            done += n;
            visited += 1;
            if visited > self.clusters {
                return Err(Error::BadChain);
            }
            match classify(self.fat_entry(cluster)?)? {
                Next::Eoc => {
                    return if done < data.len() {
                        Err(Error::BadChain)
                    } else {
                        Ok(())
                    };
                }
                Next::Data(next) => cluster = next,
            }
        }
        Ok(())
    }

    /// When a create reuses a deleted (`0xE5`) slot, LFN entries
    /// directly *before* it are stale leftovers of the entry that used
    /// to live there (LFNs always immediately precede their 8.3 entry).
    /// Clear them so a later scan can never assemble them onto the new
    /// entry — bounded to the spec's 20-entry chain cap, stopping at
    /// any non-LFN, already-deleted, or end-of-directory slot.
    pub(crate) fn clear_stale_lfn(&self, loc: DirLoc, slot: u32) -> Result<(), Error> {
        for back in 1..=MAX_LFN_ENTRIES {
            if slot < back {
                break;
            }
            let prev = slot - back;
            let byte = self.slot_byte(loc, prev)?;
            let mut raw = [0u8; 32];
            read_bytes(self.dev, byte, &mut raw)?;
            if raw[11] == 0x0F && raw[0] != 0x00 && raw[0] != 0xE5 {
                raw[0] = 0xE5;
                write_bytes(self.dev, byte, &raw)?;
            } else {
                break;
            }
        }
        Ok(())
    }

    /// Byte offset of entry `slot` inside directory `loc`. The root is
    /// bounded by its entry count (never past the region), a
    /// subdirectory slot by the cluster's entry capacity, and the
    /// cluster itself by the data region — so a slot write can never
    /// land in a FAT, past the root, or outside the volume.
    pub(crate) fn slot_byte(&self, loc: DirLoc, slot: u32) -> Result<u64, Error> {
        match loc {
            DirLoc::Root => self.root_byte(slot),
            DirLoc::Cluster(cluster) => {
                let base = self.cluster_byte(cluster)?;
                let per_cluster = self.cluster_bytes / 32;
                if slot >= per_cluster {
                    return Err(Error::BadDirectory);
                }
                Ok(base + u64::from(slot) * 32)
            }
        }
    }

    /// Update an existing entry in place: cluster, size and the write
    /// date/time — name, attributes and the (zero) FAT16 high-cluster
    /// word stay byte-identical. This is the operation's commit point.
    fn update_entry(
        &self,
        loc: DirLoc,
        slot: u32,
        cluster: u32,
        size: u32,
        date: u16,
        time: u16,
    ) -> Result<(), Error> {
        let byte = self.slot_byte(loc, slot)?;
        let mut raw = [0u8; 32];
        read_bytes(self.dev, byte, &mut raw)?;
        let lo = u16::try_from(cluster).map_err(|_| Error::BadDirectory)?;
        raw[20] = 0; // FAT16: the high cluster word must be zero
        raw[21] = 0;
        raw[22..24].copy_from_slice(&time.to_le_bytes()); // write time
        raw[24..26].copy_from_slice(&date.to_le_bytes()); // write date
        raw[26..28].copy_from_slice(&lo.to_le_bytes()); // first cluster
        raw[28..32].copy_from_slice(&size.to_le_bytes()); // size — last field written
        write_bytes(self.dev, byte, &raw)
    }

    /// Write a fresh directory entry (FS2 used attribute `0x20`; FS3
    /// passes `0x10` for a directory) into a pre-selected free slot.
    /// Only ever called after the slot run was found free, i.e. the slot
    /// is `0xE5`/`0x00`.
    #[allow(clippy::too_many_arguments)] // one 32-byte record's worth of fields
    pub(crate) fn create_entry(
        &self,
        loc: DirLoc,
        slot: u32,
        name8: &[u8; 11],
        attr: u8,
        cluster: u32,
        size: u32,
        date: u16,
        time: u16,
    ) -> Result<(), Error> {
        let raw = build_entry(name8, attr, cluster, size, date, time)?;
        write_bytes(self.dev, self.slot_byte(loc, slot)?, &raw)
    }
}
