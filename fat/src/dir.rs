//! Directory scanning, path lookup and name matching for [`Fat16`].
//!
//! Two name forms are matched against a path component, both
//! ASCII-case-insensitive: the raw **8.3** entry name (space-padded,
//! uppercased on both sides) and an assembled **LFN** (long file name).
//!
//! LFN chains are treated as evidence, never as authority: sequence
//! numbers, the "last entry" flag, the zero type/cluster fields and the
//! checksum over the following 8.3 name are all validated, and a chain
//! that fails any of them is *discarded* — lookup then falls back to the
//! 8.3 name instead of trusting a partially verified string.

use super::{BlockDevice, Error, Fat16, Next, classify, read_bytes};

/// Maximum UTF-16 units a long name may hold (FAT spec: 255 characters;
/// a surrogate pair counts twice, so the cap is on units here).
const MAX_LFN_UNITS: usize = 255;

/// Where the directory being scanned lives.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DirLoc {
    /// The fixed root region (root-entry count bounded).
    Root,
    /// A cluster chain (subdirectory). For a *slot location* this names
    /// the exact cluster holding the slot; for a *directory head* it is
    /// the chain's first cluster.
    Cluster(u32),
}

/// The parts of a directory entry the reader needs. `pub(crate)`: the
/// file-reading half in the crate root and the writer (`write` module)
/// consume it.
#[derive(Clone, Copy)]
pub(crate) struct DirEntry {
    /// First data cluster (0 = none; FAT32's high word must be 0 here).
    pub(crate) first_cluster: u32,
    /// File size in bytes (directories are not sized on FAT16).
    pub(crate) size: u32,
    /// Attribute byte (bit 0x10 = directory, 0x08 = volume label).
    attr: u8,
}

impl DirEntry {
    pub(crate) fn is_dir(&self) -> bool {
        self.attr & 0x10 != 0
    }

    /// Parse the fixed offsets of a directory entry. The FAT32-style
    /// high cluster word must be zero on a FAT16 volume; anything else
    /// is a malformed entry (fail closed instead of silently truncating
    /// the cluster number to 16 bits).
    fn from_raw(raw: &[u8; 32]) -> Result<Self, Error> {
        let high = u16::from_le_bytes([raw[20], raw[21]]);
        if high != 0 {
            return Err(Error::BadDirectory);
        }
        Ok(Self {
            first_cluster: u32::from(u16::from_le_bytes([raw[26], raw[27]])),
            size: u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
            attr: raw[11],
        })
    }
}

/// What the scan does with one raw directory entry.
enum Step {
    /// The entry (or the LFN chain preceding it) matched the name.
    Found(DirEntry),
    /// Keep scanning.
    KeepGoing,
    /// The `0x00` marker: nothing after this point is in use.
    End,
}

/// Result of [`Fat16::locate`]: either the entry was found (with the
/// exact slot it lives in, so a writer can update it in place) or the
/// parent directory resolved but the final component is absent (so a
/// writer knows where to create it).
pub(crate) enum Placement {
    /// The final component exists in directory `loc` at `slot`.
    Found {
        /// Directory *containing* the entry (the specific cluster for a
        /// subdirectory slot, [`DirLoc::Root`] for the fixed root).
        loc: DirLoc,
        /// Slot index inside `loc`.
        slot: u32,
        entry: DirEntry,
    },
    /// The final component does not exist; `parent` is the directory
    /// head a writer would create it in.
    Missing { parent: DirLoc },
}

/// Assembled long-name state while scanning one directory.
#[derive(Clone, Copy)]
struct LfnState {
    /// Sequence number of the *next* LFN entry the chain requires;
    /// 0 = no chain in progress (none started, completed, or discarded).
    expect: u8,
    /// Checksum captured from the chain's first entry.
    checksum: u8,
    /// UTF-16 units, entry `seq` landing at `(seq - 1) * 13`.
    units: [u16; MAX_LFN_UNITS],
    /// Unit slots written at least once — the valid prefix of `units`.
    filled: usize,
}

impl LfnState {
    fn new() -> Self {
        Self {
            expect: 0,
            checksum: 0,
            units: [0; MAX_LFN_UNITS],
            filled: 0,
        }
    }

    fn reset(&mut self) {
        self.expect = 0;
        self.checksum = 0;
        self.filled = 0;
    }

    /// Fold one LFN directory entry into the chain, validating the
    /// sequence as it goes. Any violation discards the chain (see the
    /// module docs) — never a panic, never a partially trusted name.
    fn push(&mut self, raw: &[u8; 32]) {
        let seq = raw[0];
        let idx = seq & 0x1F;
        let last = seq & 0x40 != 0;
        // FAT spec §7.4: sequence 1..=20, type byte and first-cluster
        // field must be zero.
        if raw[12] != 0 || raw[26] != 0 || raw[27] != 0 || idx == 0 || idx > 20 {
            self.reset();
            return;
        }
        if self.expect == 0 {
            // A chain is read highest-sequence first, flagged 0x40.
            if !last {
                self.reset();
                return;
            }
            self.expect = idx;
            self.checksum = raw[13];
            self.filled = 0;
        } else if last || idx != self.expect {
            self.reset();
            return;
        }

        // 13 UTF-16 units per entry: bytes 1..11, 14..26, 28..32.
        let base = usize::from(idx - 1) * 13;
        for k in 0..13usize {
            let from = match k {
                0..=4 => 1 + k * 2,
                5..=10 => 14 + (k - 5) * 2,
                _ => 28 + (k - 11) * 2,
            };
            let unit = u16::from_le_bytes([raw[from], raw[from + 1]]);
            let slot = base + k;
            if slot < MAX_LFN_UNITS {
                self.units[slot] = unit;
                if slot + 1 > self.filled {
                    self.filled = slot + 1;
                }
            }
            // Units past the 255-unit cap are ignored (a name that long
            // cannot exist; truncating beats refusing the whole chain).
        }
        self.expect = idx - 1; // 0 once seq 1 was folded in
    }

    /// Seal the chain against the 8.3 entry it precedes; `None` when
    /// there is no complete, checksum-matching chain (including when
    /// the chain was discarded earlier).
    fn finish(&mut self, short: &[u8; 32]) -> Option<([u16; MAX_LFN_UNITS], usize)> {
        if self.filled == 0 || self.expect != 0 || self.checksum != short_checksum(short) {
            self.reset();
            return None;
        }
        let len = self.units[..self.filled]
            .iter()
            .position(|&u| u == 0)
            .unwrap_or(self.filled); // a name may fill all 255 units
        if len == 0 {
            self.reset();
            return None;
        }
        let sealed = (self.units, len);
        self.reset();
        Some(sealed)
    }
}

/// The FAT spec's LFN checksum over an entry's raw 11-byte 8.3 name.
fn short_checksum(short: &[u8; 32]) -> u8 {
    short[..11].iter().fold(0u8, |sum, &c| {
        // Rotate right by one, then add — wrapping, per spec.
        (((sum & 1) << 7) | (sum >> 1)).wrapping_add(c)
    })
}

/// Fold ASCII lowercase to uppercase, leaving everything else (including
/// surrogate halves) untouched — the one case rule both name forms use.
fn fold_ascii(unit: u16) -> u16 {
    if (0x61..=0x7A).contains(&unit) {
        unit - 0x20
    } else {
        unit
    }
}

/// Compare a UTF-8 path component with an assembled UTF-16 long name,
/// ASCII-case-insensitively. Returns `false` on any mismatch; a `char`
/// outside the BMP contributes its surrogate pair.
fn utf16_eq(component: &str, units: &[u16]) -> bool {
    let mut it = units.iter().copied();
    for c in component.chars() {
        let cp = u32::from(c);
        let (hi, lo) = if cp > 0xFFFF {
            let rest = cp - 0x10000;
            (
                (0xD800 + (rest >> 10)) as u16,
                Some((0xDC00 + (rest & 0x3FF)) as u16),
            )
        } else {
            (cp as u16, None)
        };
        // Fold *both* sides: the long name keeps whatever case the
        // writer stored, the path keeps whatever the caller typed.
        match it.next() {
            Some(u) if fold_ascii(u) == fold_ascii(hi) => {}
            _ => return false,
        }
        if let Some(lo) = lo {
            match it.next() {
                Some(u) if fold_ascii(u) == fold_ascii(lo) => {}
                _ => return false,
            }
        }
    }
    it.next().is_none()
}

/// Compare a path component with the entry's raw 8.3 name: split on the
/// first `.`, uppercase both sides, space-pad to 8+3 and compare. The
/// component's shape is checked first so a name that *cannot* be 8.3
/// (empty base, >8/ >3 bytes, non-ASCII or control bytes) falls through
/// to the LFN comparison instead of matching by accident.
fn short_matches(raw: &[u8; 32], component: &str) -> bool {
    let bytes = component.as_bytes();
    let (base, ext) = match bytes.iter().position(|&b| b == b'.') {
        Some(i) => (&bytes[..i], &bytes[i + 1..]),
        None => (bytes, &[][..]),
    };
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return false;
    }
    let mut want = [b' '; 11];
    for (slot, &c) in want.iter_mut().zip(base) {
        if !c.is_ascii() || c.is_ascii_control() {
            return false;
        }
        *slot = c.to_ascii_uppercase();
    }
    for (slot, &c) in want[8..].iter_mut().zip(ext) {
        if !c.is_ascii() || c.is_ascii_control() {
            return false;
        }
        *slot = c.to_ascii_uppercase();
    }
    raw[..11]
        .iter()
        .zip(want.iter())
        .all(|(&r, &w)| r.to_ascii_uppercase() == w)
}

impl<'a, D: BlockDevice + ?Sized> Fat16<'a, D> {
    /// Resolve an absolute path to its directory entry (read path
    /// convenience over [`locate`](Self::locate)).
    pub(crate) fn resolve(&self, path: &str) -> Result<Option<DirEntry>, Error> {
        Ok(match self.locate(path)? {
            Placement::Found { entry, .. } => Some(entry),
            Placement::Missing { .. } => None,
        })
    }

    /// Resolve an absolute path to its **slot**: where the entry lives
    /// (`Placement::Found`) or, when the final component is absent, the
    /// existing parent directory a writer would create it in
    /// (`Placement::Missing`).
    ///
    /// `.`/`..` are *refused*, not interpreted (a root filesystem has no
    /// need for traversal and refusing removes the whole class of
    /// escape); the same holds for empty components and non-absolute
    /// paths — [`Error::Path`]. A missing *intermediate* component is
    /// [`Error::NotFound`] (nothing can be created below a directory
    /// that does not exist — this crate has no `mkdir`); a missing final
    /// component is `Placement::Missing`. Both readings collapse to
    /// `NotFound` for the read path, exactly as before FS2.
    pub(crate) fn locate(&self, path: &str) -> Result<Placement, Error> {
        let mut rest = path.strip_prefix('/').ok_or(Error::Path)?;
        if rest.is_empty() {
            return Err(Error::Path);
        }
        let mut loc = DirLoc::Root;
        loop {
            let (component, tail) = match rest.find('/') {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            };
            if component.is_empty() || component == "." || component == ".." {
                return Err(Error::Path);
            }
            let Some((entry_loc, slot, entry)) = self.scan_dir(loc, component)? else {
                return match tail {
                    None | Some("") => Ok(Placement::Missing { parent: loc }),
                    Some(_) => Err(Error::NotFound),
                };
            };
            match tail {
                None => {
                    return Ok(Placement::Found {
                        loc: entry_loc,
                        slot,
                        entry,
                    });
                }
                Some("") => {
                    // A trailing slash must name a directory.
                    if !entry.is_dir() {
                        return Err(Error::Path);
                    }
                    return Ok(Placement::Found {
                        loc: entry_loc,
                        slot,
                        entry,
                    });
                }
                Some(t) => {
                    if !entry.is_dir() {
                        return Err(Error::NotAFile);
                    }
                    if entry.first_cluster < 2 {
                        return Err(Error::BadDirectory);
                    }
                    loc = DirLoc::Cluster(entry.first_cluster);
                    rest = t;
                }
            }
        }
    }

    /// Scan one directory for `name`, stopping at the first match or at
    /// the directory's own end. Both forms of end are bounded: the root
    /// by its entry count, a subdirectory by its (cycle-checked) chain.
    /// On a match the entry's exact slot location travels with it.
    fn scan_dir(&self, dir: DirLoc, name: &str) -> Result<Option<(DirLoc, u32, DirEntry)>, Error> {
        let mut lfn = LfnState::new();
        match dir {
            DirLoc::Root => {
                for index in 0..self.root_entries {
                    let mut raw = [0u8; 32];
                    read_bytes(self.dev, self.root_byte(index)?, &mut raw)?;
                    match self.consider(&raw, name, &mut lfn)? {
                        Step::Found(entry) => return Ok(Some((DirLoc::Root, index, entry))),
                        Step::KeepGoing => {}
                        Step::End => break,
                    }
                }
            }
            DirLoc::Cluster(mut cluster) => {
                let per_cluster = self.cluster_bytes / 32; // ≥ 16: clusters are ≥ 512 B
                let mut visited = 0u32;
                loop {
                    let base = self.cluster_byte(cluster)?;
                    visited += 1;
                    if visited > self.clusters {
                        return Err(Error::BadChain); // cyclic directory chain
                    }
                    for slot in 0..per_cluster {
                        let mut raw = [0u8; 32];
                        read_bytes(self.dev, base + u64::from(slot) * 32, &mut raw)?;
                        match self.consider(&raw, name, &mut lfn)? {
                            Step::Found(entry) => {
                                return Ok(Some((DirLoc::Cluster(cluster), slot, entry)));
                            }
                            Step::KeepGoing => {}
                            Step::End => return Ok(None),
                        }
                    }
                    match classify(self.fat_entry(cluster)?)? {
                        Next::Eoc => return Ok(None),
                        Next::Data(next) => cluster = next,
                    }
                }
            }
        }
        Ok(None)
    }

    /// Decide what one raw directory entry means for this lookup.
    fn consider(&self, raw: &[u8; 32], name: &str, lfn: &mut LfnState) -> Result<Step, Error> {
        match raw[0] {
            0x00 => return Ok(Step::End),
            0xE5 => {
                lfn.reset(); // a deleted entry also invalidates its chain
                return Ok(Step::KeepGoing);
            }
            _ => {}
        }
        if raw[11] == 0x0F {
            lfn.push(raw);
            return Ok(Step::KeepGoing);
        }
        let long = lfn.finish(raw);
        if raw[11] & 0x08 != 0 {
            return Ok(Step::KeepGoing); // volume label, not a file
        }
        if short_matches(raw, name)
            || long.is_some_and(|(units, len)| utf16_eq(name, &units[..len]))
        {
            return Ok(Step::Found(DirEntry::from_raw(raw)?));
        }
        Ok(Step::KeepGoing)
    }
}
