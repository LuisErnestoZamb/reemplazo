//! **FAT16** reader (FS1, `FAT_OK`) + writer (FS2, `FS_WRITE_OK`) — the
//! filesystem half of the installer milestones (`cargo xtask
//! smoke-install`).
//!
//! # Why this crate exists (dependency policy exception (a))
//!
//! Milestone FS1 was ordered to probe `fatfs = "0.3"` first and adopt it
//! if it built `no_std` for `x86_64-unknown-none`. The probe **failed**
//! (recorded in the FS1 commit): `fatfs` 0.3.6's `no_std` mode is wired
//! through the `core_io` crate (`#[cfg(not(feature = "std"))] extern
//! crate core_io;` in its `lib.rs`), and `core_io`'s build script maps
//! the *exact rustc commit hash* to a config table —
//! `mappings.iter().find(...).expect("Unknown compiler version, upgrade
//! core_io?")` panics on Rust 1.98.1, so the crate cannot build for the
//! kernel target at all. `fatfs`'s own docs are the citation `docs/
//! installer.md` §5/§9.1 already carries for this evaluation; no other
//! maintained `no_std` FAT reader was adopted because the milestone's
//! dependency policy admits **no new crates besides `fatfs`**.
//!
//! So: from-scratch, `#![no_std]`, `#![forbid(unsafe_code)]`, zero
//! dependencies — parsing and writing are pure byte arithmetic over a
//! [`BlockDevice`] the caller supplies, which is exactly what makes it
//! host-testable (`tests/hostile.rs` feeds crafted in-memory images,
//! `tests/write.rs` drives the write path against a model).
//!
//! # What is validated before a single cluster is touched
//!
//! Every boot-sector field the FAT spec defines is checked against the
//! device before any of it is used: jump instruction, bytes/sector ∈
//! {512,1024,2048,4096}, sectors/cluster power of two with a 32 KiB
//! cluster cap, reserved sectors ≠ 0, FAT count ∈ {1,2}, root-entry
//! count ≠ 0, total sectors (16- and 32-bit forms) non-zero and *inside
//! the device*, media descriptor, `FATsz16 ≠ 0` (≠ 0 ⇒ FAT32, refused),
//! the `55 AA` signature at offset `bps-2`, the region arithmetic
//! (reserved + FATs + root ≤ total), the cluster count inside the FAT16
//! window 4085..=65524, and the first FAT entry mirroring the media
//! descriptor. Anything that would read outside the device is refused
//! by [`checked_end`] before the read is issued.
//!
//! # Bounded by construction
//!
//! - every read is range-checked against `size_bytes()` ([`checked_end`]),
//! - a cluster chain walk visits at most `clusters` clusters, so a
//!   **cyclic FAT fails with [`Error::BadChain`] instead of hanging**,
//! - a directory scan is bounded by the root-entry count (fixed root) or
//!   by the cluster chain (subdirectory), again cycle-checked,
//! - `read_file` refuses a size larger than the caller's buffer *before*
//!   walking anything ([`Error::BufferTooSmall`]).
//!
//! Indices into the fixed `[u8; 512]`/`[u8; 32]` scratch buffers below
//! are always compile-time constants smaller than the buffer; every
//! quantity *derived from disk data* goes through checked arithmetic.
//!
//! # Documented v1 limits
//!
//! FAT16 only (FAT12 and FAT32 volumes are refused as [`Error::NotFat16`]),
//! ASCII-case-insensitive lookup, no `/./`-style path syntax
//! (`.`, `..` and empty components are refused — [`Error::Path`]), and
//! long names are capped at 255 UTF-16 units.
//!
//! # FS2: the write slice
//!
//! [`Fat16::write_file`] (create-or-overwrite) and [`Fat16::create_file`]
//! (refuses to clobber — [`Error::Exists`]) implement the minimal honest
//! write set: create a file in the root directory *or in an existing
//! subdirectory* (no `mkdir` — creating directories is not supported),
//! overwrite in place, grow the cluster chain, truncate and free the
//! tail. The full policy lives in [`write`]'s module docs; the headline
//! points:
//!
//! - **Write-through, no `flush()`.** Every FAT sector, data sector and
//!   directory sector is written to the device inside the operation, in
//!   the order FAT → data → directory entry (the entry is the single
//!   field readers consult, so it acts as the operation's commit point).
//!   **Crash consistency is explicitly NOT a goal of FS2** — no journal,
//!   no flush barriers, no drive `FLUSH CACHE`; power-loss ordering is a
//!   later milestone.
//! - **Names must be 8.3-encodable** (see [`write`]): long names are
//!   *refused* ([`Error::InvalidName`]), short names are uppercased —
//!   this crate never writes LFN entries.
//! - Every refusal is fail-closed and panic-free: disk full
//!   ([`Error::NoSpace`]), out-of-range/corrupt chains
//!   ([`Error::BadChain`], reusing the FS1 validators), a device without
//!   write support ([`Error::ReadOnly`], the [`BlockDevice::write_at`]
//!   default), a bad timestamp ([`Error::Stamp`]).
//!
//! Timestamps come from the caller (the kernel passes its RTC reading, a
//! fixed documented value when the clock is dead) — this crate never
//! invents a clock.

#![no_std]
#![forbid(unsafe_code)]

mod dir;
/// The formatter (mkfs): [`format::format_fat16`] derives the FAT16
/// geometry from the device size and writes boot sector + FATs + root,
/// self-checked against this crate's own reader — shared by xtask's
/// `write_disk_image` and the kernel's installer (docs/installer.md
/// §8.1 → §8.3).
pub mod format;
pub use format::{FormatOpts, Geometry, format_fat16, geometry, geometry_with};
/// The write half (FS2): [`write::Stamp`] and the writer's module docs
/// (ordering, naming rule, refusals) live here.
pub mod write;
pub use write::Stamp;
/// Device-sector granularity the block layer speaks (ATA PIO moves
/// 512-byte sectors). [`BlockDevice`] implementations must expose a
/// capacity that is a whole number of these.
const DEV_SECTOR: u64 = 512;

/// Cluster sizes above this are refused (Microsoft FAT spec: a cluster
/// is at most 32 KiB).
const MAX_CLUSTER_BYTES: u32 = 32 * 1024;

/// Inclusive cluster-count window that defines a FAT16 volume (Microsoft
/// FAT spec §7: 4085..=65524; below is FAT12, above is FAT32).
const FAT16_MIN_CLUSTERS: u32 = 4085;
const FAT16_MAX_CLUSTERS: u32 = 65524;

/// Why a mount, lookup or read was refused — printed via `{:?}` on the
/// kernel's `FATAL: fs: …` line. Every variant is fail-closed: nothing
/// in this crate ever recovers from one by guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The device is smaller than one sector, or a read would start or
    /// end outside `size_bytes()`.
    OutOfRange,
    /// The block device refused a read (transfer error).
    Read,
    /// The volume is too small to hold even its boot sector.
    TooSmall,
    /// Bytes `bps-2..bps` of the first sector are not `55 AA`.
    BadSignature,
    /// The boot sector does not start with a jump (`EB`/`E9`).
    BadJump,
    /// Bytes/sector is not one of 512, 1024, 2048, 4096.
    BadBytesPerSector,
    /// Sectors/cluster is zero, not a power of two, or yields a cluster
    /// larger than 32 KiB.
    BadSectorsPerCluster,
    /// Reserved-sector count is zero (nothing holds the boot sector).
    BadReserved,
    /// FAT count is neither 1 nor 2.
    BadFatCount,
    /// Root-entry count is zero (a FAT16 volume needs a fixed root) or
    /// multiplying it by 32 overflowed.
    BadRootEntries,
    /// Total-sector count (16- or 32-bit form) is zero.
    BadTotalSectors,
    /// Media descriptor is implausible, or the first FAT entry does not
    /// mirror it.
    BadMedia,
    /// `FATsz16` is zero — that marks a FAT32 volume (out of scope), or
    /// FAT count × FAT size overflowed.
    BadFatSize,
    /// Not a FAT16 volume: cluster count outside 4085..=65524.
    NotFat16,
    /// The volume's own structures (reserved + FATs + root) fall outside
    /// the declared total sectors.
    Truncated,
    /// No such path.
    NotFound,
    /// The path names a directory (or a non-directory where a directory
    /// was required on the way to the file).
    NotAFile,
    /// The file is larger than the caller's output buffer.
    BufferTooSmall,
    /// Malformed cluster chain: cycle (more hops than the volume has
    /// clusters), free/reserved/bad cluster inside a chain, a cluster
    /// index outside the data region, or a chain that ends before the
    /// declared size is reached.
    BadChain,
    /// Malformed directory entry (FAT32-style high cluster word on a
    /// FAT16 volume).
    BadDirectory,
    /// Malformed path: not absolute, empty, or a `.`/`..` component
    /// (no path syntax is interpreted in v1).
    Path,
    /// A write was attempted on a [`BlockDevice`] that has no write
    /// support — the default [`BlockDevice::write_at`] refuses this way,
    /// so read-only adapters (and any caller holding one) fail closed.
    ReadOnly,
    /// The block device refused a write (transfer error).
    Write,
    /// No free cluster to grow into, or no free directory slot to create
    /// a file in (disk/directory full).
    NoSpace,
    /// The name is not 8.3-encodable — see [`write`]'s naming rule.
    /// This crate never writes LFN entries, so long or exotic names are
    /// refused rather than silently mangled.
    InvalidName,
    /// [`Fat16::create_file`] on a path that already exists (use
    /// [`Fat16::write_file`] to create-or-overwrite).
    Exists,
    /// The caller's timestamp falls outside FAT's representable range
    /// (year 1980..=2107, valid month/day/hour/minute/second).
    Stamp,
}

/// The minimal block surface the filesystem needs — rule of three:
/// reads, writes, and capacity (no flushes, no geometry beyond
/// capacity).
///
/// Implementations are expected to:
/// - report a capacity that is a whole number of 512-byte sectors,
/// - accept any 512-byte-aligned offset whose whole range lies inside
///   `size_bytes()`,
/// - refuse anything else with [`Error::OutOfRange`] rather than
///   reading or writing past the end.
///
/// [`write_at`](BlockDevice::write_at) has a default implementation that
/// refuses with [`Error::ReadOnly`]: a read-only adapter stays
/// read-only without saying anything, and the write tests can prove the
/// refusal path exists. Devices that support writes override it with the
/// same alignment/range contract as `read_at`.
pub trait BlockDevice {
    /// Total capacity in bytes.
    fn size_bytes(&self) -> u64;
    /// Read `buf.len()` bytes starting at byte `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error>;
    /// Write `buf.len()` bytes starting at byte `offset`.
    ///
    /// Default: refuse with [`Error::ReadOnly`] (read-only devices stay
    /// read-only). Overriding implementations get the same contract as
    /// `read_at`: whole 512-byte sectors, 512-byte-aligned offsets,
    /// range-checked against `size_bytes()`, [`Error::OutOfRange`]
    /// otherwise. Writes are **write-through**: `Ok` means the bytes
    /// reached the device — there is no cache and no `flush()` in this
    /// crate (see [`write`]'s ordering docs).
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        let _ = (offset, buf);
        Err(Error::ReadOnly)
    }
}

/// The single place an offset+length pair is validated: `Ok(end)` only
/// when `offset + buf.len()` does not overflow **and** stays inside the
/// device. Exposed so adapters (and the kernel's ATA adapter) share one
/// tested definition of "inside".
pub fn checked_end(size: u64, offset: u64, len: usize) -> Result<u64, Error> {
    // `len as u64`: usize is at most 64 bits on every target we build
    // for, so the widening conversion cannot lose information.
    let end = offset.checked_add(len as u64).ok_or(Error::OutOfRange)?;
    if end > size {
        return Err(Error::OutOfRange);
    }
    Ok(end)
}

/// Read `buf` at an arbitrary (not necessarily sector-aligned) byte
/// offset, moving whole device sectors through a 512-byte scratch and
/// slicing out what the caller asked for.
///
/// The range is validated once up front ([`checked_end`]); because the
/// device capacity is a whole number of sectors, every scratch read that
/// follows is guaranteed to sit inside it.
fn read_bytes<D: BlockDevice + ?Sized>(dev: &D, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
    checked_end(dev.size_bytes(), offset, buf.len())?;
    let mut done = 0usize;
    while done < buf.len() {
        let abs = offset + done as u64;
        let sector = abs / DEV_SECTOR;
        let within = (abs - sector * DEV_SECTOR) as usize;
        let n = core::cmp::min(DEV_SECTOR as usize - within, buf.len() - done);
        let mut scratch = [0u8; DEV_SECTOR as usize];
        dev.read_at(sector * DEV_SECTOR, &mut scratch)?;
        buf[done..done + n].copy_from_slice(&scratch[within..within + n]);
        done += n;
    }
    Ok(())
}

/// Write `buf` at an arbitrary byte offset — the mirror of
/// [`read_bytes`], and the *only* way the writer touches the device
/// outside whole-cluster data copies. FAT entries (2 B) and directory
/// entries (32 B) are not sector-aligned, so each touched sector is
/// read-modify-written through a 512-byte scratch: the untouched bytes
/// of the sector (neighbouring FAT entries, the rest of a directory
/// sector, padding inside a cluster) are preserved byte-for-byte.
///
/// The range is validated once up front ([`checked_end`]), and the
/// device contract guarantees every scratch write stays inside it.
fn write_bytes<D: BlockDevice + ?Sized>(dev: &D, offset: u64, buf: &[u8]) -> Result<(), Error> {
    checked_end(dev.size_bytes(), offset, buf.len())?;
    let mut done = 0usize;
    while done < buf.len() {
        let abs = offset + done as u64;
        let sector = abs / DEV_SECTOR;
        let within = (abs - sector * DEV_SECTOR) as usize;
        let n = core::cmp::min(DEV_SECTOR as usize - within, buf.len() - done);
        let mut scratch = [0u8; DEV_SECTOR as usize];
        dev.read_at(sector * DEV_SECTOR, &mut scratch)?;
        scratch[within..within + n].copy_from_slice(&buf[done..done + n]);
        dev.write_at(sector * DEV_SECTOR, &scratch)?;
        done += n;
    }
    Ok(())
}

/// Classification of a FAT16 table entry during a chain walk.
enum Next {
    /// A data-cluster index (not yet range-checked against the volume).
    Data(u32),
    /// End-of-chain marker (`0xFFF8..=0xFFFF`).
    Eoc,
}

/// Classify one raw FAT16 entry. Free (`0x0000`), reserved (`0x0001`,
/// `0xFFF0..=0xFFF6`) and bad (`0xFFF7`) values are [`Error::BadChain`],
/// not silent stops: a file's cluster chain must end on an explicit
/// end-of-chain marker, so a chain that dissolves into free space is
/// corruption.
fn classify(raw: u16) -> Result<Next, Error> {
    match raw {
        0x0000 | 0x0001 | 0xFFF0..=0xFFF7 => Err(Error::BadChain),
        0xFFF8..=0xFFFF => Ok(Next::Eoc),
        _ => Ok(Next::Data(u32::from(raw))),
    }
}

/// A mounted read-only FAT16 volume.
///
/// `D` is the caller's block device: the kernel passes its ATA drive,
/// the tests pass an in-memory image. `?Sized` keeps trait objects
/// possible without costing anything here.
pub struct Fat16<'a, D: BlockDevice + ?Sized> {
    dev: &'a D,
    /// Bytes per *filesystem* sector (512/1024/2048/4096).
    bps: u32,
    /// Bytes per cluster (sectors/cluster × bps, ≤ 32 KiB).
    cluster_bytes: u32,
    /// Number of FAT copies (1 or 2 — validated at mount). Writes keep
    /// every copy in sync (FS2).
    fat_count: u32,
    /// Filesystem sectors per FAT copy (validated nonzero at mount and
    /// large enough to hold every cluster entry — FS2 hardening).
    fat_sectors: u32,
    /// Filesystem sector where FAT #0 starts.
    fat_start: u32,
    /// Filesystem sector where the fixed root directory starts.
    root_start: u32,
    /// Root directory entries (fixed-size region, nonzero by validation).
    root_entries: u32,
    /// Filesystem sector of the data region — i.e. of cluster 2.
    data_start: u32,
    /// Data-cluster count, validated to be inside the FAT16 window.
    clusters: u32,
}

impl<'a, D: BlockDevice + ?Sized> Fat16<'a, D> {
    /// Parse and validate the boot sector, then freeze the geometry.
    ///
    /// Every failure mode is an [`Error`]; a volume that does not look
    /// exactly like a well-formed FAT16 volume over *this* device is
    /// refused rather than mounted with hedges.
    pub fn mount(dev: &'a D) -> Result<Self, Error> {
        let size = dev.size_bytes();
        if size < DEV_SECTOR {
            return Err(Error::TooSmall);
        }

        // The BPB (offsets 11..62) always fits in the first 512 bytes
        // even when the filesystem sector is larger.
        let mut b = [0u8; 512];
        read_bytes(dev, 0, &mut b)?;

        if b[0] != 0xEB && b[0] != 0xE9 {
            return Err(Error::BadJump);
        }

        let bps = u32::from(u16::from_le_bytes([b[11], b[12]]));
        if !matches!(bps, 512 | 1024 | 2048 | 4096) {
            return Err(Error::BadBytesPerSector);
        }

        // The `55 AA` signature closes the first *filesystem* sector,
        // i.e. it lives at `bps - 2` (offset 510 only when bps == 512).
        let sig_ok = if bps == 512 {
            b[510] == 0x55 && b[511] == 0xAA
        } else {
            let mut sig = [0u8; 2];
            read_bytes(dev, u64::from(bps) - 2, &mut sig)?;
            sig == [0x55, 0xAA]
        };
        if !sig_ok {
            return Err(Error::BadSignature);
        }

        let spc = u32::from(b[13]);
        if spc == 0 || !spc.is_power_of_two() {
            return Err(Error::BadSectorsPerCluster);
        }
        let cluster_bytes = spc.checked_mul(bps).ok_or(Error::BadSectorsPerCluster)?;
        if cluster_bytes > MAX_CLUSTER_BYTES {
            return Err(Error::BadSectorsPerCluster);
        }

        let reserved = u32::from(u16::from_le_bytes([b[14], b[15]]));
        if reserved == 0 {
            return Err(Error::BadReserved);
        }

        let fat_count = u32::from(b[16]);
        if fat_count != 1 && fat_count != 2 {
            return Err(Error::BadFatCount);
        }

        let root_entries = u32::from(u16::from_le_bytes([b[17], b[18]]));
        if root_entries == 0 {
            return Err(Error::BadRootEntries);
        }

        let total16 = u32::from(u16::from_le_bytes([b[19], b[20]]));
        let total32 = u32::from_le_bytes([b[32], b[33], b[34], b[35]]);
        let total = if total32 != 0 { total32 } else { total16 };
        if total == 0 {
            return Err(Error::BadTotalSectors);
        }

        let media = b[21];
        if media != 0xF0 && media < 0xF8 {
            return Err(Error::BadMedia);
        }

        let fat_sectors = u32::from(u16::from_le_bytes([b[22], b[23]]));
        if fat_sectors == 0 {
            // `FATsz16 == 0` is the FAT32 marker (the real size lives in
            // the extended BPB). Out of scope for this read-only v1.
            return Err(Error::NotFat16);
        }

        // The whole declared volume must live inside the device before
        // any region inside it is used.
        let volume_bytes = u64::from(total)
            .checked_mul(u64::from(bps))
            .ok_or(Error::OutOfRange)?;
        if volume_bytes > size {
            return Err(Error::OutOfRange);
        }

        let root_bytes = root_entries.checked_mul(32).ok_or(Error::BadRootEntries)?;
        let root_sectors = root_bytes.div_ceil(bps);
        let fat_total = fat_count
            .checked_mul(fat_sectors)
            .ok_or(Error::BadFatSize)?;
        let root_start = reserved.checked_add(fat_total).ok_or(Error::Truncated)?;
        let data_start = root_start
            .checked_add(root_sectors)
            .ok_or(Error::Truncated)?;
        if data_start >= total {
            return Err(Error::Truncated);
        }
        let clusters = (total - data_start) / spc;
        if !(FAT16_MIN_CLUSTERS..=FAT16_MAX_CLUSTERS).contains(&clusters) {
            return Err(Error::NotFat16);
        }

        // FS2 hardening: each FAT copy must physically hold every
        // cluster entry the data region can produce (`clusters + 2`
        // entries × 2 bytes, entries 0 and 1 included). Without this a
        // fat_entry/fat_set for a high cluster would spill past the FAT
        // into the next FAT copy or the root directory. `clusters` is
        // ≤ 65524, so `clusters + 2` cannot overflow u32.
        let fat_bytes = u64::from(fat_sectors) * u64::from(bps);
        if u64::from(clusters + 2) * 2 > fat_bytes {
            return Err(Error::BadFatSize);
        }

        // Spec: FAT[0]'s low byte mirrors the media descriptor. Reading
        // it also proves the FAT region is inside the device.
        let mut fat0 = [0u8; 2];
        read_bytes(dev, u64::from(reserved) * u64::from(bps), &mut fat0)?;
        if fat0[0] != media {
            return Err(Error::BadMedia);
        }

        Ok(Self {
            dev,
            bps,
            cluster_bytes,
            fat_count,
            fat_sectors,
            fat_start: reserved,
            root_start,
            root_entries,
            data_start,
            clusters,
        })
    }

    /// Read the whole file at absolute `path` into `out`, returning the
    /// byte count.
    ///
    /// Fails with [`Error::BufferTooSmall`] when the directory entry's
    /// size exceeds `out`, so the walk below is bounded by the caller's
    /// own buffer. The chain is walked to its **explicit** end-of-chain
    /// marker (data is copied only while `size` bytes are still due):
    /// a chain that ends early means the size lies beyond it, and the
    /// `visited > clusters` guard turns a cyclic FAT into
    /// [`Error::BadChain`] instead of a hang. Clusters past the declared
    /// size are tolerated (some writers pad) but still hop-checked.
    pub fn read_file(&self, path: &str, out: &mut [u8]) -> Result<usize, Error> {
        let entry = self.resolve(path)?.ok_or(Error::NotFound)?;
        if entry.is_dir() {
            return Err(Error::NotAFile);
        }
        let size = entry.size as usize;
        if size > out.len() {
            return Err(Error::BufferTooSmall);
        }
        if size == 0 {
            return Ok(0); // an empty file needs no chain at all
        }

        let cs = self.cluster_bytes as usize;
        let mut done = 0usize;
        let mut cluster = entry.first_cluster;
        let mut visited = 0u32;
        loop {
            if done < size {
                let byte = self.cluster_byte(cluster)?;
                let n = core::cmp::min(cs, size - done);
                read_bytes(self.dev, byte, &mut out[done..done + n])?;
                done += n;
            }
            // Cycle guard: a chain may never visit more clusters than
            // the volume has, so a cyclic FAT fails instead of hanging.
            visited += 1;
            if visited > self.clusters {
                return Err(Error::BadChain);
            }
            match classify(self.fat_entry(cluster)?)? {
                Next::Eoc => break,
                Next::Data(next) => cluster = next,
            }
        }
        if done < size {
            return Err(Error::BadChain); // size lies beyond the chain
        }
        Ok(size)
    }

    /// Byte offset of the start of `cluster`; refuses any index outside
    /// `2..=clusters + 1`.
    fn cluster_byte(&self, cluster: u32) -> Result<u64, Error> {
        if cluster < 2 || cluster > self.clusters + 1 {
            return Err(Error::BadChain);
        }
        let in_data = u64::from(cluster - 2)
            .checked_mul(u64::from(self.cluster_bytes))
            .ok_or(Error::OutOfRange)?;
        in_data
            .checked_add(u64::from(self.data_start) * u64::from(self.bps))
            .ok_or(Error::OutOfRange)
    }

    /// FAT #0 entry for `cluster`, validated to the data region.
    fn fat_entry(&self, cluster: u32) -> Result<u16, Error> {
        if cluster < 2 || cluster > self.clusters + 1 {
            return Err(Error::BadChain);
        }
        let byte = u64::from(self.fat_start) * u64::from(self.bps) + u64::from(cluster) * 2;
        let mut entry = [0u8; 2];
        read_bytes(self.dev, byte, &mut entry)?;
        Ok(u16::from_le_bytes([entry[0], entry[1]]))
    }

    /// Byte offset of root-directory entry `index` (bounds-checked by
    /// the region's entry count, so a scan can never step into the FATs
    /// or the data region).
    fn root_byte(&self, index: u32) -> Result<u64, Error> {
        if index >= self.root_entries {
            return Err(Error::BadDirectory);
        }
        Ok(u64::from(self.root_start) * u64::from(self.bps) + u64::from(index) * 32)
    }
}
