//! FAT16 **formatter** (mkfs) — the shared half of the installer's
//! format step (docs/installer.md §8.1's xtask formatter, extracted so
//! kernel *and* xtask format through the same code, and the same host
//! tests).
//!
//! # Why the formatter lives here
//!
//! FS1 wrote the FAT16 geometry by hand inside `xtask` (fixed 64 MiB
//! layout). The installer (milestone I1) needs the *same* formatter
//! inside the kernel to format the target disk's data partition — so
//! the geometry code moved into this crate as [`format_fat16`], and
//! xtask's `write_disk_image` now calls it too (one implementation,
//! one contract, tested once against this crate's own reader).
//!
//! # Geometry (computed, not assumed)
//!
//! Unlike FS1's fixed constants, the geometry is *derived from the
//! device size*: sectors/cluster doubles through 1,2,4,…,64 until the
//! cluster count lands inside the FAT16 window (4085..=65524, the
//! Microsoft spec's §7 definition this crate's reader enforces), the
//! FAT size is sized from an upper bound on the cluster count (so the
//! table physically holds every entry — the invariant
//! [`Fat16::mount`](crate::Fat16::mount) re-checks), and a device that
//! cannot reach the window at any cluster size is refused
//! ([`Error::TooSmall`] below ~4085 clusters, [`Error::NotFat16`]
//! above what 32 KiB clusters can hold). The pure selector is
//! [`geometry`], so the huge-disk refusal is host-tested without
//! allocating a huge image.
//!
//! # What is written
//!
//! One boot sector (spec-shaped: jump, OEM, BPB with every field
//! [`Fat16::mount`] validates, `hidden_sectors` carrying the partition
//! offset when formatting inside a partition, extended signature,
//! volume id/label, `"FAT16   "` type string, `55 AA`), two identical
//! FATs (`0xFFF8, 0xFFFF, 0x0000…` — cluster 2 stays *free* for the
//! first `write_file`), and a zeroed fixed root directory. The rest of
//! the device is left untouched (a sparse hole on the host, whatever
//! was there on a partition — formatting never zeroes the data
//! region).
//!
//! The function **re-mounts the result through [`Fat16::mount`]
//! before returning**: a formatter whose output our own reader would
//! refuse fails right here, not later in a QEMU run.
//!
//! # Bounded by construction
//!
//! every write is one 512-byte sector inside the device, issued in a
//! loop bounded by the geometry (~530 writes for any FAT16 device);
//! no buffer larger than one sector exists; all intermediate cluster
//! arithmetic is `u64` and checked against the device size first.

use crate::{BlockDevice, Error, Fat16};

/// Cluster-count window that defines a FAT16 volume (Microsoft FAT
/// spec §7 — same constants the reader enforces).
const FAT16_MIN_CLUSTERS: u32 = 4085;
const FAT16_MAX_CLUSTERS: u32 = 65524;

/// Fixed FAT16 shape (spec-shaped, independent of device size):
/// 512-byte sectors, one reserved sector, two FATs, 512 root entries
/// (16 root sectors), 63 sectors/track, 255 heads — the values
/// `mkfs.fat` and GRUB's `fat.mod` expect on a PC.
const BPS: u32 = 512;
const RESERVED: u32 = 1;
const FAT_COUNT: u32 = 2;
const ROOT_ENTRIES: u32 = 512;
const ROOT_SECTORS: u32 = ROOT_ENTRIES * 32 / BPS;
const SPT: u16 = 63;
const HEADS: u16 = 255;
const MEDIA: u8 = 0xF8;

/// The chosen FAT16 layout for a device of `total_sectors` sectors —
/// everything the formatter writes and everything a caller (or test)
/// may want to assert about the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    /// Sectors per cluster (1..=64 → 512 B..=32 KiB clusters).
    pub sectors_per_cluster: u32,
    /// Sectors per FAT copy.
    pub fat_sectors: u32,
    /// Data-region cluster count (inside 4085..=65524).
    pub clusters: u32,
    /// Total sectors (the device's, floored to whole sectors).
    pub total_sectors: u32,
    /// Filesystem sector where the data region (cluster 2) starts.
    pub data_start_sector: u32,
}

/// Pick the FAT16 geometry for `total_sectors` — the pure, host-testable
/// heart of [`format_fat16`]:
///
/// - smallest `sectors_per_cluster` in 1,2,4,…,64 whose cluster count
///   fits the FAT16 window (a bigger cluster size means fewer
///   clusters, so the first fit is also the finest granularity),
/// - FAT size from an *upper bound* on the cluster count
///   (`total / spc` ≥ actual clusters), so every entry physically
///   fits (the reader re-verifies at mount),
/// - [`Error::TooSmall`] when even 512 B clusters cannot reach 4085
///   clusters, [`Error::NotFat16`] when even 32 KiB clusters stay
///   above 65524 (or the sector count does not fit FAT16's 32-bit
///   total field at all).
pub fn geometry(total_sectors: u32) -> Result<Geometry, Error> {
    if total_sectors == 0 {
        return Err(Error::TooSmall);
    }
    let root_sectors = ROOT_SECTORS;
    let mut too_small = false;
    for spc in [1u32, 2, 4, 8, 16, 32, 64] {
        // Upper bound on clusters; u64 so `est + 2` can never wrap
        // even for a absurd total.
        let est = u64::from(total_sectors) / u64::from(spc);
        let fat = ((est + 2) * 2).div_ceil(u64::from(BPS));
        let overhead = u64::from(RESERVED + root_sectors) + u64::from(FAT_COUNT) * fat;
        let Some(data) = u64::from(total_sectors).checked_sub(overhead) else {
            too_small = true; // structures don't even fit at this spc
            continue;
        };
        let clusters = (data / u64::from(spc)) as u32;
        if clusters > FAT16_MAX_CLUSTERS {
            continue; // need bigger clusters
        }
        if clusters < FAT16_MIN_CLUSTERS {
            too_small = true; // bigger spc only shrinks the count
            continue;
        }
        // FAT must hold `clusters + 2` 16-bit entries — by
        // construction (fat was sized from `est >= clusters`), but
        // re-derive with checked math rather than trusting the story.
        let fat = u32::try_from(fat).map_err(|_| Error::BadFatSize)?;
        if u64::from(clusters + 2) * 2 > u64::from(fat) * u64::from(BPS) {
            return Err(Error::BadFatSize);
        }
        return Ok(Geometry {
            sectors_per_cluster: spc,
            fat_sectors: fat,
            clusters,
            total_sectors,
            data_start_sector: RESERVED + FAT_COUNT * fat + root_sectors,
        });
    }
    Err(if too_small {
        Error::TooSmall
    } else {
        Error::NotFat16
    })
}

/// Options for [`format_fat16`] — the fields a real mkfs takes beyond
/// the device itself.
#[derive(Debug, Clone, Copy)]
pub struct FormatOpts<'a> {
    /// 11-byte volume label (space-padded), e.g. `b"REEMPLAZO  "`.
    /// Must be printable ASCII — refused otherwise, never mangled.
    pub label: &'a [u8; 11],
    /// Volume ID (any 32-bit value; callers may derive it from a
    /// timestamp — this crate never invents a clock).
    pub volume_id: u32,
    /// Partition start LBA when formatting inside a partition (the
    /// BPB's "hidden sectors" field); 0 for a superfloppy.
    pub hidden_sectors: u32,
}

/// Format `dev` as a FAT16 volume ([`FormatOpts`]), writing boot
/// sector, both FATs and the zeroed root directory; returns the
/// computed [`Geometry`].
///
/// Refuses (before writing anything): a device that is not a whole
/// number of 512-byte sectors or too small for any FAT16 layout, a
/// non-printable label, a device without write support, and — last
/// line of defense — a result [`Fat16::mount`] would not accept
/// (self-check).
pub fn format_fat16<D: BlockDevice + ?Sized>(
    dev: &D,
    opts: &FormatOpts<'_>,
) -> Result<Geometry, Error> {
    let size = dev.size_bytes();
    if size < u64::from(BPS) || !size.is_multiple_of(u64::from(BPS)) {
        return Err(Error::TooSmall);
    }
    let total64 = size / u64::from(BPS);
    if total64 > u64::from(u32::MAX) {
        return Err(Error::NotFat16); // past FAT's 32-bit total field
    }
    if opts.label.iter().any(|&b| !(0x20..=0x7E).contains(&b)) {
        return Err(Error::InvalidName);
    }
    let geo = geometry(total64 as u32)?;

    // --- Boot sector (every field `Fat16::mount` validates) ---
    let mut boot = [0u8; BPS as usize];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // jump over the BPB
    boot[3..11].copy_from_slice(b"MSDOS5.0"); // OEM name
    boot[11..13].copy_from_slice(&(BPS as u16).to_le_bytes());
    boot[13] = geo.sectors_per_cluster as u8;
    boot[14..16].copy_from_slice(&(RESERVED as u16).to_le_bytes());
    boot[16] = FAT_COUNT as u8;
    boot[17..19].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
    if geo.total_sectors <= 0xFFFF {
        boot[19..21].copy_from_slice(&(geo.total_sectors as u16).to_le_bytes());
        // TotSec32 stays 0 when TotSec16 carries the value (spec).
    } else {
        boot[32..36].copy_from_slice(&geo.total_sectors.to_le_bytes());
    }
    boot[21] = MEDIA;
    boot[22..24].copy_from_slice(&(geo.fat_sectors as u16).to_le_bytes());
    boot[24..26].copy_from_slice(&SPT.to_le_bytes());
    boot[26..28].copy_from_slice(&HEADS.to_le_bytes());
    boot[28..32].copy_from_slice(&opts.hidden_sectors.to_le_bytes());
    boot[36] = 0x80; // drive number
    boot[38] = 0x29; // extended boot signature → next three fields valid
    boot[39..43].copy_from_slice(&opts.volume_id.to_le_bytes());
    boot[43..54].copy_from_slice(opts.label);
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;
    dev.write_at(0, &boot)?;

    // --- FATs: media + end-of-chain in entries 0/1, cluster 2 free ---
    let mut fat_sector = [0u8; BPS as usize];
    fat_sector[0..4].copy_from_slice(&[0xF8, 0xFF, 0xFF, 0xFF]);
    for copy in 0..FAT_COUNT {
        let base = u64::from(RESERVED + copy * geo.fat_sectors) * u64::from(BPS);
        dev.write_at(base, &fat_sector)?;
        for s in 1..geo.fat_sectors {
            dev.write_at(base + u64::from(s) * u64::from(BPS), &[0u8; BPS as usize])?;
        }
    }

    // --- Zeroed fixed root directory ---
    let root_base = u64::from(RESERVED + FAT_COUNT * geo.fat_sectors) * u64::from(BPS);
    for s in 0..ROOT_SECTORS {
        dev.write_at(
            root_base + u64::from(s) * u64::from(BPS),
            &[0u8; BPS as usize],
        )?;
    }

    // Self-check: our own reader must accept what we just wrote —
    // a formatter/reader contract break fails here, not in QEMU.
    Fat16::mount(dev)?;
    Ok(geo)
}
