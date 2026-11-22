//! GPT (GUID Partition Table) reader + writer — the installer's
//! partition-table layer (docs/installer.md §2(3), §3.2, §4, milestone
//! `INST_OK`).
//!
//! # Why this crate exists (dependency-policy exception (a))
//!
//! docs/installer.md §2(3) fixes the design: *partitioning/formatting is
//! implemented in the installer itself — "the OS partitions itself" is
//! not a shortcut, it is the only option* (no `sfdisk`/`gdisk` in the
//! tools image, nothing on the target but our own kernel), and §3.2
//! budgets the CRC32 as "~20-line table-driven CRC32 — we have no CRC32
//! today". So: from-scratch, `#![no_std]`, `#![forbid(unsafe_code)]`,
//! zero dependencies — pure byte arithmetic over a [`Device`] the
//! caller supplies, which is exactly what makes it host-testable
//! (`tests/hostile.rs` feeds crafted in-memory images, including ones
//! written by [`write`] and then corrupted field by field).
//!
//! # What is validated before a single byte is trusted
//!
//! Reading ([`read`]) checks, in order, every field the format defines
//! against the *device* it claims to describe:
//!
//! - protective MBR: `55 AA` signature, at least one partition record
//!   with type `0xEE`, start LBA 1 and a non-zero size (the legacy CHS
//!   bytes and the boot-code area are explicitly *not* validated —
//!   they are unused for protective partitions; garbage there is
//!   accepted on purpose, see the hostile tests),
//! - header: `"EFI PART"` signature, revision `0x00010000`, header
//!   size 92..=512, **CRC-32 over the header with the CRC field
//!   zeroed**, reserved word zero, `current_lba` matching the header's
//!   own location, `backup_lba` matching the device's last LBA,
//!   usable range ordered and inside the device,
//! - entry array: count ≥ 1 and ≤ [`MAX_ENTRIES`] (128 — a hard cap, a
//!   `u32::MAX` count from a corrupt disk is refused before any
//!   allocation or loop), entry size exactly 128, the array inside the
//!   device and outside the usable range on both sides (primary and
//!   backup), and the array's CRC-32,
//! - every partition: non-empty type, `first ≤ last`, both LBAs inside
//!   the usable range, and **pairwise non-overlap** (bounded:
//!   128²/2 comparisons),
//! - backup header at the last LBA: signature/CRC again, mirrored
//!   fields (`backup_lba == 1`, usable range, count, entry size, entry
//!   CRC, disk GUID), the backup entry array at the exact mirrored
//!   offset, and the **bytes** of the backup array re-checksummed — a
//!   backup that disagrees with the primary fails as [`Error::BadBackup`].
//!
//! Every read is range-checked against [`Device::size_bytes`] with
//! checked arithmetic ([`lba_bytes`] is the single choke point), so a
//! hostile header can never make the parser read outside the device.
//!
//! Writing ([`write`]) builds a fixed, standard layout — protective
//! MBR, header at LBA1, 128 × 128 B entries at LBA2 (32 sectors),
//! mirrored backup at the end — and validates the caller's partitions
//! (non-empty, ordered, inside the usable range, non-overlapping)
//! *before* touching the device. The MBR is written **last**: its
//! `55 AA` is the commit point that makes the table visible.
//!
//! # Documented v1 limits
//!
//! - 512-byte sectors only (what the ATA PIO driver moves),
//! - entry size exactly 128 B and at most 128 entries (what we write;
//!   a foreign disk using 256-entry arrays is refused, loudly),
//! - no kernel GUID generation (the caller passes fixed GUIDs — v1
//!   installs are byte-reproducible; per-install randomness is future
//!   work),
//! - MBR-style extended partitions, RAID and hybrid MBRs are out of
//!   scope (refused, never guessed).

#![no_std]
#![forbid(unsafe_code)]

mod crc32;
pub use crc32::crc32;

/// Device sector size — the ATA PIO layer moves 512-byte sectors, so
/// the whole format is defined on them (4K-native disks are refused by
/// the alignment checks, not silently rounded).
pub const SECTOR: u64 = 512;

/// Hard cap on partition entries. The UEFI default is 128 (16 KiB of
/// entry array — 32 sectors, mirrored at the end); a corrupt or
/// hostile header claiming more is refused as [`Error::BadEntryArray`]
/// *before* any storage is committed to it, which is what keeps the
/// parser's memory fixed at ~15 KiB regardless of disk contents.
pub const MAX_ENTRIES: usize = 128;

/// Bytes per partition entry (UEFI spec: 128 × 2^n, we require 128).
pub const ENTRY_BYTES: usize = 128;

/// Defined GPT header size (UEFI spec §5.2: 92 bytes for revision
/// 1.0); the CRC covers exactly this many bytes.
pub const HEADER_BYTES: usize = 92;

/// Header revision 1.0.
const REVISION: u32 = 0x0001_0000;

/// Why a parse or write was refused — printed via `{:?}` on the
/// kernel's `FATAL: install: …` line. Every variant is fail-closed:
/// nothing in this crate ever recovers from one by guessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The device is smaller than the format's arithmetic floor, or not
    /// a whole number of 512-byte sectors.
    TooSmall,
    /// The device refused a read (transfer error).
    Read,
    /// The device refused a write (transfer error).
    Write,
    /// A write on a [`Device`] that has no write support (the default
    /// [`Device::write_at`]).
    ReadOnly,
    /// A read or write would start or end outside `size_bytes()`, or a
    /// 64-bit LBA→byte conversion overflowed.
    OutOfRange,
    /// LBA0 is not a protective MBR: bad `55 AA`, no `0xEE` record,
    /// start LBA ≠ 1, or zero size.
    BadProtectiveMbr,
    /// Header signature is not `"EFI PART"`.
    BadSignature,
    /// Header revision is not 1.0.
    BadRevision,
    /// Header size outside 92..=512.
    BadHeaderSize,
    /// Header CRC-32 mismatch (computed with the CRC field zeroed).
    BadHeaderCrc,
    /// The header's reserved word (offset 20) is not zero.
    BadReserved,
    /// `current_lba` does not match the LBA the header was read from.
    BadCurrentLba,
    /// `backup_lba` does not match the device's last LBA (primary) or
    /// is not 1 (backup).
    BadBackupLba,
    /// Usable range inverted or reaching outside the device.
    BadUsableRange,
    /// Entry count (0, > [`MAX_ENTRIES`]) or entry size (≠ 128) is
    /// unusable, or the entry array falls outside the device / inside
    /// the usable range.
    BadEntryArray,
    /// The primary entry array's CRC-32 does not match its header.
    BadEntriesCrc,
    /// The backup header/array disagrees with the primary (mirrored
    /// fields, offset, or the backup array's own bytes).
    BadBackup,
    /// A partition is empty in a written layout, has `first > last`,
    /// or falls outside the usable range.
    BadPartition,
    /// Two partitions overlap.
    Overlap,
    /// More than [`MAX_ENTRIES`] partitions handed to [`write`].
    TooManyPartitions,
    /// A partition name is longer than 36 units or not ASCII (names
    /// are written as UTF-16; this crate accepts plain ASCII only).
    Name,
}

/// The minimal device surface GPT needs — same contract as
/// `fat::BlockDevice`: whole 512-byte sectors at 512-byte-aligned
/// offsets, everything range-checked against [`size_bytes`](Device::size_bytes),
/// anything else refused with [`Error::OutOfRange`].
///
/// [`write_at`](Device::write_at) has a default implementation that
/// refuses with [`Error::ReadOnly`]: a read-only adapter (the hostile
/// *read* tests) stays read-only, and [`write`]'s refusal path stays
/// testable. Implementations that support writes override it with the
/// same alignment/range contract.
pub trait Device {
    /// Total capacity in bytes.
    fn size_bytes(&self) -> u64;
    /// Read `buf.len()` bytes starting at byte `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error>;
    /// Write `buf.len()` bytes starting at byte `offset`.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        let _ = (offset, buf);
        Err(Error::ReadOnly)
    }
}

/// A 128-bit GUID in **on-disk byte order** (GPT stores the first
/// three fields little-endian — mixed-endian — so the raw 16 bytes are
/// the interchange format; [`core::fmt::Debug`] re-hyphenates them into
/// the canonical textual form).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub [u8; 16]);

impl core::fmt::Debug for Guid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let b = &self.0;
        // Data1/Data2/Data3 are stored little-endian, Data4 as-is
        // (UEFI spec §5.2.2 GUID byte layout).
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

impl Guid {
    /// The all-zero GUID — GPT's "unused entry" marker.
    pub const ZERO: Self = Self([0u8; 16]);

    /// From the 16 on-disk bytes (mixed-endian, as stored).
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0 == [0u8; 16]
    }
}

/// `Microsoft basic data partition` — `EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`
/// (the type docs/installer.md §3.2 gives p2; the GUID is the standard
/// one, confirmed against Microsoft's `PARTITION_BASIC_DATA_GUID`).
pub const TYPE_BASIC_DATA: Guid = Guid([
    0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
]);

/// `BIOS boot partition` — `21686148-6449-6E6F-744E-656564454649`
/// (docs/installer.md §3.2's p1; GRUB's `grub-bios-setup` writes
/// `core.img` into exactly this type of partition per the GRUB manual
/// §BIOS installation).
pub const TYPE_BIOS_GRUB: Guid = Guid([
    0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49,
]);

/// One GPT partition entry (128 bytes on disk).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    /// Entry name as 36 UTF-16 code units (the format's fixed field).
    /// We only ever *write* ASCII here; on read the bytes are raw
    /// untrusted data — callers that print it must sanitize (the
    /// kernel never prints disk-sourced names).
    pub name: [u16; 36],
}

impl Partition {
    /// An entry with the given type/unique GUIDs and LBA range, no
    /// name. `const` so the kernel can build its layout from literals.
    pub const fn new(type_guid: Guid, unique_guid: Guid, first_lba: u64, last_lba: u64) -> Self {
        Self {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            name: [0u16; 36],
        }
    }

    /// The all-zero entry GPT uses for unused slots.
    pub(crate) const fn empty() -> Self {
        Self::new(Guid::ZERO, Guid::ZERO, 0, 0)
    }

    /// True when the entry carries no type GUID (an unused slot).
    pub fn is_empty(&self) -> bool {
        self.type_guid.is_zero()
    }

    /// Set the entry name from ASCII (encoded as UTF-16, padded with
    /// NULs). Refuses non-ASCII or more than 36 bytes — never
    /// truncates, never guesses ([`Error::Name`]).
    pub fn with_name(mut self, ascii: &[u8]) -> Result<Self, Error> {
        if ascii.len() > self.name.len() {
            return Err(Error::Name);
        }
        for (i, &b) in ascii.iter().enumerate() {
            if !b.is_ascii() {
                return Err(Error::Name);
            }
            self.name[i] = u16::from(b);
        }
        Ok(self)
    }
}

/// A validated GPT: the fields the header defines plus every non-empty
/// partition, in entry-array order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gpt {
    pub disk_guid: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    /// LBA of the primary header (always 1 for the disks we read —
    /// retained so callers can report it).
    pub header_lba: u64,
    /// LBA of the backup header (the device's last LBA).
    pub backup_lba: u64,
    partitions: [Partition; MAX_ENTRIES],
    count: usize,
}

impl Gpt {
    /// Every non-empty partition, in entry-array order.
    pub fn partitions(&self) -> &[Partition] {
        &self.partitions[..self.count]
    }
}

/// The fixed layout [`write`] produces, expressed as the usable range
/// (single source of truth for callers that must predict where their
/// partitions fit: the installer computes `p2.last` from this, xtask's
/// host-side verifier re-derives it from the image size).
///
/// `None` when the device cannot hold the layout (protective MBR +
/// header + 32 primary entry sectors + backup mirror + header — the
/// arithmetic floor is 68 sectors, and at least one usable sector must
/// remain between the mirrors).
pub fn usable_range(size_bytes: u64) -> Option<(u64, u64)> {
    if size_bytes < 68 * SECTOR || !size_bytes.is_multiple_of(SECTOR) {
        return None;
    }
    let total = size_bytes / SECTOR;
    let last = total - 1;
    let entry_sectors = (MAX_ENTRIES * ENTRY_BYTES) as u64 / SECTOR; // 32
    let first_usable = 2 + entry_sectors; // after header (LBA1) + entries
    let backup_entries_start = last - entry_sectors;
    let last_usable = backup_entries_start - 1;
    if last_usable < first_usable {
        return None;
    }
    Some((first_usable, last_usable))
}

/// LBA → byte offset, the single choke point every disk-derived LBA
/// passes through: checked multiply, then (by callers) a range check
/// against the device before the transfer is issued.
fn lba_bytes(lba: u64) -> Result<u64, Error> {
    lba.checked_mul(SECTOR).ok_or(Error::OutOfRange)
}

/// A parsed header (all multi-byte fields already decoded).
struct Header {
    current_lba: u64,
    backup_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: Guid,
    entries_start: u64,
    num_entries: u32,
    entry_size: u32,
    entries_crc: u32,
}

/// Decode one fixed little-endian field of a 512-byte sector. The
/// offsets are compile-time constants inside the buffer — no index is
/// ever derived from disk data.
fn le32(sector: &[u8; 512], offset: usize) -> u32 {
    u32::from_le_bytes([
        sector[offset],
        sector[offset + 1],
        sector[offset + 2],
        sector[offset + 3],
    ])
}

fn le64(sector: &[u8; 512], offset: usize) -> u64 {
    u64::from_le_bytes([
        sector[offset],
        sector[offset + 1],
        sector[offset + 2],
        sector[offset + 3],
        sector[offset + 4],
        sector[offset + 5],
        sector[offset + 6],
        sector[offset + 7],
    ])
}

/// Validate one 512-byte sector as a GPT header (signature, revision,
/// size, CRC with the field zeroed, reserved word). The *positional*
/// checks (`current_lba`, `backup_lba`, mirrored fields) are done by
/// the caller, which knows which copy it is looking at.
fn parse_header(sector: &[u8; 512]) -> Result<Header, Error> {
    if sector.get(0..8) != Some(b"EFI PART") {
        return Err(Error::BadSignature);
    }
    if le32(sector, 8) != REVISION {
        return Err(Error::BadRevision);
    }
    let header_size = u16::from_le_bytes([sector[12], sector[13]]) as usize;
    if !(HEADER_BYTES..=SECTOR as usize).contains(&header_size) {
        return Err(Error::BadHeaderSize);
    }
    // CRC-32 over the header with its own CRC field zeroed (UEFI
    // spec §5.2 step 4).
    let mut zeroed = *sector;
    zeroed[16..20].fill(0);
    if crc32::crc32(&zeroed[..header_size]) != le32(sector, 16) {
        return Err(Error::BadHeaderCrc);
    }
    if le32(sector, 20) != 0 {
        return Err(Error::BadReserved);
    }
    Ok(Header {
        current_lba: le64(sector, 24),
        backup_lba: le64(sector, 32),
        first_usable: le64(sector, 40),
        last_usable: le64(sector, 48),
        disk_guid: Guid([
            sector[56], sector[57], sector[58], sector[59], sector[60], sector[61], sector[62],
            sector[63], sector[64], sector[65], sector[66], sector[67], sector[68], sector[69],
            sector[70], sector[71],
        ]),
        entries_start: le64(sector, 72),
        num_entries: le32(sector, 80),
        entry_size: le32(sector, 84),
        entries_crc: le32(sector, 88),
    })
}

/// Read and validate the header at `lba` (range-checked against the
/// device before the read is issued).
fn read_header<D: Device + ?Sized>(dev: &D, lba: u64) -> Result<Header, Error> {
    let offset = lba_bytes(lba)?;
    let end = offset.checked_add(SECTOR).ok_or(Error::OutOfRange)?;
    if end > dev.size_bytes() {
        return Err(Error::OutOfRange);
    }
    let mut sector = [0u8; SECTOR as usize];
    dev.read_at(offset, &mut sector)?;
    parse_header(&sector)
}

/// Structural checks shared by the primary and backup entry-array
/// regions: count and size usable, array inside the device and outside
/// the usable range (on the correct side).
fn check_entries_region(header: &Header, device_last_lba: u64, backup: bool) -> Result<(), Error> {
    if header.num_entries == 0
        || header.num_entries as usize > MAX_ENTRIES
        || header.entry_size != ENTRY_BYTES as u32
    {
        return Err(Error::BadEntryArray);
    }
    let entry_bytes = u64::from(header.num_entries) * ENTRY_BYTES as u64;
    let start = lba_bytes(header.entries_start)?;
    let end = start.checked_add(entry_bytes).ok_or(Error::OutOfRange)?;
    if backup {
        // Backup array must sit entirely after the usable range and
        // end before the backup header's own LBA.
        if header.entries_start <= header.last_usable {
            return Err(Error::BadEntryArray);
        }
        if end > lba_bytes(device_last_lba)? {
            return Err(Error::BadEntryArray);
        }
    } else {
        // Primary array must sit at/after LBA2 (LBA0 MBR + LBA1
        // header) and end before the usable range starts.
        if header.entries_start < 2 {
            return Err(Error::BadEntryArray);
        }
        if end > lba_bytes(header.first_usable)? {
            return Err(Error::BadEntryArray);
        }
    }
    Ok(())
}

/// Decode one 128-byte entry slot. An all-zero type marks an unused
/// slot (returned empty; the rest of the slot is ignored — GPT only
/// defines the type GUID as the presence flag). A non-empty entry's
/// LBA range must be ordered and inside the usable range.
fn parse_entry(bytes: &[u8], first_usable: u64, last_usable: u64) -> Result<Partition, Error> {
    let slot: &[u8; ENTRY_BYTES] = bytes.try_into().map_err(|_| Error::BadEntryArray)?;
    let mut type_bytes = [0u8; 16];
    type_bytes.copy_from_slice(&slot[0..16]);
    let type_guid = Guid(type_bytes);
    if type_guid.is_zero() {
        return Ok(Partition::empty());
    }
    let mut unique_bytes = [0u8; 16];
    unique_bytes.copy_from_slice(&slot[16..32]);
    let mut first = [0u8; 8];
    first.copy_from_slice(&slot[32..40]);
    let mut last = [0u8; 8];
    last.copy_from_slice(&slot[40..48]);
    let first_lba = u64::from_le_bytes(first);
    let last_lba = u64::from_le_bytes(last);
    if first_lba > last_lba || first_lba < first_usable || last_lba > last_usable {
        return Err(Error::BadPartition);
    }
    let mut name = [0u16; 36];
    for (i, unit) in name.iter_mut().enumerate() {
        let lo = slot[48 + 2 * i];
        let hi = slot[48 + 2 * i + 1];
        *unit = u16::from_le_bytes([lo, hi]);
    }
    Ok(Partition {
        type_guid,
        unique_guid: Guid(unique_bytes),
        first_lba,
        last_lba,
        name,
    })
}

/// Walk the entry array at `entries_lba` sector by sector and decode
/// the non-empty entries into `out` (the array's CRC is *not* checked
/// here — [`read`] checksums the bytes first, so a corrupted array is
/// refused as [`Error::BadEntriesCrc`] before any entry is parsed).
/// Returns the number of non-empty entries.
fn parse_entries<D: Device + ?Sized>(
    dev: &D,
    entries_lba: u64,
    num_entries: u32,
    first_usable: u64,
    last_usable: u64,
    out: &mut [Partition; MAX_ENTRIES],
) -> Result<usize, Error> {
    let entry_bytes = u64::from(num_entries) * ENTRY_BYTES as u64;
    let sectors = entry_bytes.div_ceil(SECTOR);
    let mut remaining = entry_bytes;
    let mut count = 0usize;
    let mut index = 0u64;
    for s in 0..sectors {
        let lba = entries_lba.checked_add(s).ok_or(Error::OutOfRange)?;
        let mut sector = [0u8; SECTOR as usize];
        dev.read_at(lba_bytes(lba)?, &mut sector)?;
        let n = core::cmp::min(SECTOR, remaining) as usize;
        let mut offset = 0usize;
        while offset + ENTRY_BYTES <= n && index < u64::from(num_entries) {
            let entry = parse_entry(
                &sector[offset..offset + ENTRY_BYTES],
                first_usable,
                last_usable,
            )?;
            if !entry.is_empty() {
                // `index < num_entries <= MAX_ENTRIES`, so this can
                // never overflow the array — belt and braces anyway.
                let slot = out.get_mut(count).ok_or(Error::TooManyPartitions)?;
                *slot = entry;
                count += 1;
            }
            offset += ENTRY_BYTES;
            index += 1;
        }
        remaining -= n as u64;
    }
    Ok(count)
}

/// CRC-only walk of an entry array (used for the backup mirror, whose
/// *bytes* must match the primary's header CRC — the parsed primary
/// entries already live in the caller's array).
fn entries_crc<D: Device + ?Sized>(
    dev: &D,
    entries_lba: u64,
    num_entries: u32,
) -> Result<u32, Error> {
    let entry_bytes = u64::from(num_entries) * ENTRY_BYTES as u64;
    let sectors = entry_bytes.div_ceil(SECTOR);
    let mut crc = crc32::Crc32::new();
    let mut remaining = entry_bytes;
    for s in 0..sectors {
        let lba = entries_lba.checked_add(s).ok_or(Error::OutOfRange)?;
        let mut sector = [0u8; SECTOR as usize];
        dev.read_at(lba_bytes(lba)?, &mut sector)?;
        let n = core::cmp::min(SECTOR, remaining) as usize;
        crc.update(&sector[..n]);
        remaining -= n as u64;
    }
    Ok(crc.finish())
}

/// Refuse any partition pair whose LBA ranges intersect (touching
/// endpoints are legal: `a.last + 1 == b.first`).
fn check_overlap(partitions: &[Partition]) -> Result<(), Error> {
    for (i, a) in partitions.iter().enumerate() {
        for b in partitions.iter().skip(i + 1) {
            if !(a.last_lba < b.first_lba || b.last_lba < a.first_lba) {
                return Err(Error::Overlap);
            }
        }
    }
    Ok(())
}

/// Parse and validate the whole GPT on `dev` — protective MBR, primary
/// header + entries, backup header + entries (byte-level CRC) — and
/// return the validated table. Every failure mode is an [`Error`]; a
/// table that does not check out *exactly* is refused, never mounted
/// with hedges.
pub fn read<D: Device + ?Sized>(dev: &D) -> Result<Gpt, Error> {
    let size = dev.size_bytes();
    // Arithmetic floor: MBR + primary header + ≥1 entry sector + ≥1
    // usable sector + ≥1 backup entry sector + backup header.
    if size < 6 * SECTOR || !size.is_multiple_of(SECTOR) {
        return Err(Error::TooSmall);
    }
    let total = size / SECTOR;
    let last = total - 1;

    // --- Protective MBR (legacy CHS + boot code intentionally ignored) ---
    let mut mbr = [0u8; SECTOR as usize];
    dev.read_at(0, &mut mbr)?;
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(Error::BadProtectiveMbr);
    }
    let protective = (0..4).any(|i| {
        let record = 446 + 16 * i;
        let start_lba = u32::from_le_bytes([
            mbr[record + 8],
            mbr[record + 9],
            mbr[record + 10],
            mbr[record + 11],
        ]);
        let size_lba = u32::from_le_bytes([
            mbr[record + 12],
            mbr[record + 13],
            mbr[record + 14],
            mbr[record + 15],
        ]);
        mbr[record + 4] == 0xEE && start_lba == 1 && size_lba != 0
    });
    if !protective {
        return Err(Error::BadProtectiveMbr);
    }

    // --- Primary header at LBA1 ---
    let primary = read_header(dev, 1)?;
    if primary.current_lba != 1 {
        return Err(Error::BadCurrentLba);
    }
    if primary.backup_lba != last {
        return Err(Error::BadBackupLba);
    }
    if primary.first_usable < 2
        || primary.first_usable > primary.last_usable
        || primary.last_usable >= total
    {
        return Err(Error::BadUsableRange);
    }
    check_entries_region(&primary, last, false)?;

    // --- Primary entries: CRC the bytes *first*, then decode ---
    let array_crc = entries_crc(dev, primary.entries_start, primary.num_entries)?;
    if array_crc != primary.entries_crc {
        return Err(Error::BadEntriesCrc);
    }
    let mut partitions = [Partition::empty(); MAX_ENTRIES];
    let count = parse_entries(
        dev,
        primary.entries_start,
        primary.num_entries,
        primary.first_usable,
        primary.last_usable,
        &mut partitions,
    )?;
    check_overlap(&partitions[..count])?;

    // --- Backup header at the last LBA: must mirror the primary ---
    let backup = read_header(dev, last)?;
    if backup.current_lba != last {
        return Err(Error::BadCurrentLba);
    }
    if backup.backup_lba != 1 {
        return Err(Error::BadBackupLba);
    }
    if backup.disk_guid != primary.disk_guid
        || backup.first_usable != primary.first_usable
        || backup.last_usable != primary.last_usable
        || backup.num_entries != primary.num_entries
        || backup.entry_size != primary.entry_size
        || backup.entries_crc != primary.entries_crc
    {
        return Err(Error::BadBackup);
    }
    check_entries_region(&backup, last, true)?;
    // The backup array must occupy the exact mirror of the primary
    // (entries end where the backup header begins).
    let entry_sectors = (u64::from(primary.num_entries) * ENTRY_BYTES as u64).div_ceil(SECTOR);
    let expected_backup_start = last.checked_sub(entry_sectors).ok_or(Error::BadBackup)?;
    if backup.entries_start != expected_backup_start {
        return Err(Error::BadBackup);
    }
    // ... and its bytes must actually CRC to the shared value: a
    // corrupt backup array fails here even though every header field
    // looks right.
    if entries_crc(dev, backup.entries_start, backup.num_entries)? != array_crc {
        return Err(Error::BadBackup);
    }

    Ok(Gpt {
        disk_guid: primary.disk_guid,
        first_usable: primary.first_usable,
        last_usable: primary.last_usable,
        header_lba: 1,
        backup_lba: last,
        partitions,
        count,
    })
}

/// The variable half of a header sector (everything [`build_header`]
/// fills in besides the fixed preamble).
struct HeaderSpec {
    current_lba: u64,
    backup_lba: u64,
    first_usable: u64,
    last_usable: u64,
    disk_guid: Guid,
    entries_start: u64,
    entries_crc: u32,
}

/// Assemble a header sector: fields in place, then CRC-32 over the
/// first [`HEADER_BYTES`] bytes with the CRC field itself zeroed.
fn build_header(buf: &mut [u8; SECTOR as usize], spec: HeaderSpec) {
    buf[0..8].copy_from_slice(b"EFI PART");
    buf[8..12].copy_from_slice(&REVISION.to_le_bytes());
    buf[12..14].copy_from_slice(&(HEADER_BYTES as u16).to_le_bytes());
    // buf[16..20] (CRC) stays zero for the computation below.
    buf[24..32].copy_from_slice(&spec.current_lba.to_le_bytes());
    buf[32..40].copy_from_slice(&spec.backup_lba.to_le_bytes());
    buf[40..48].copy_from_slice(&spec.first_usable.to_le_bytes());
    buf[48..56].copy_from_slice(&spec.last_usable.to_le_bytes());
    buf[56..72].copy_from_slice(&spec.disk_guid.0);
    buf[72..80].copy_from_slice(&spec.entries_start.to_le_bytes());
    buf[80..84].copy_from_slice(&(MAX_ENTRIES as u32).to_le_bytes());
    buf[84..88].copy_from_slice(&(ENTRY_BYTES as u32).to_le_bytes());
    buf[88..92].copy_from_slice(&spec.entries_crc.to_le_bytes());
    let crc = crc32::crc32(&buf[..HEADER_BYTES]);
    buf[16..20].copy_from_slice(&crc.to_le_bytes());
}

/// Write a complete GPT describing `partitions` to `dev` (fixed
/// 128-entry layout — see [`usable_range`]).
///
/// Order: primary entries → primary header → backup entries → backup
/// header → **protective MBR last**, so the `55 AA` signature is the
/// commit point: a torn write leaves either the previous table (or a
/// blank disk) visible, never a signed table pointing at half-written
/// entries. The caller's layout is fully validated first — nothing is
/// written when it would fail.
pub fn write<D: Device + ?Sized>(
    dev: &D,
    disk_guid: Guid,
    partitions: &[Partition],
) -> Result<(), Error> {
    let size = dev.size_bytes();
    let (first_usable, last_usable) = usable_range(size).ok_or(Error::TooSmall)?;
    let total = size / SECTOR;
    let last = total - 1;
    if partitions.is_empty() {
        return Err(Error::BadPartition);
    }
    if partitions.len() > MAX_ENTRIES {
        return Err(Error::TooManyPartitions);
    }
    for p in partitions {
        if p.is_empty() || p.first_lba > p.last_lba {
            return Err(Error::BadPartition);
        }
        if p.first_lba < first_usable || p.last_lba > last_usable {
            return Err(Error::BadPartition);
        }
    }
    check_overlap(partitions)?;

    // Entry array: caller's entries first, the rest all-zero slots.
    let mut entries = [0u8; MAX_ENTRIES * ENTRY_BYTES];
    for (i, p) in partitions.iter().enumerate() {
        let offset = i * ENTRY_BYTES;
        entries[offset..offset + 16].copy_from_slice(&p.type_guid.0);
        entries[offset + 16..offset + 32].copy_from_slice(&p.unique_guid.0);
        entries[offset + 32..offset + 40].copy_from_slice(&p.first_lba.to_le_bytes());
        entries[offset + 40..offset + 48].copy_from_slice(&p.last_lba.to_le_bytes());
        for (j, unit) in p.name.iter().enumerate() {
            entries[offset + 48 + 2 * j..offset + 50 + 2 * j].copy_from_slice(&unit.to_le_bytes());
        }
        // bytes 112..128 of each slot stay zero (reserved).
    }
    let entries_crc = crc32::crc32(&entries);
    let entry_sectors = (MAX_ENTRIES * ENTRY_BYTES) as u64 / SECTOR;
    let backup_entries_start = last - entry_sectors;

    let mut primary = [0u8; SECTOR as usize];
    build_header(
        &mut primary,
        HeaderSpec {
            current_lba: 1,
            backup_lba: last,
            first_usable,
            last_usable,
            disk_guid,
            entries_start: 2,
            entries_crc,
        },
    );
    let mut backup = [0u8; SECTOR as usize];
    build_header(
        &mut backup,
        HeaderSpec {
            current_lba: last,
            backup_lba: 1,
            first_usable,
            last_usable,
            disk_guid,
            entries_start: backup_entries_start,
            entries_crc,
        },
    );

    // Protective MBR: one `0xEE` record covering LBA1..end. Starting
    // CHS = 0/0/2 (the CHS of LBA1 at 63 sectors/track) and ending CHS
    // = 0xFFFFFF ("not representable"), the values UEFI spec Table 17
    // documents (quoted in util-linux/util-linux#485); the legacy CHS
    // fields are ignored by GRUB and firmware for protective
    // partitions (osdev GPT) — LBA/size are authoritative.
    let mut mbr = [0u8; SECTOR as usize];
    let record = 446;
    mbr[record] = 0x00; // not bootable
    mbr[record + 1..record + 4].copy_from_slice(&[0x00, 0x02, 0x00]);
    mbr[record + 4] = 0xEE;
    mbr[record + 5..record + 8].copy_from_slice(&[0xFF, 0xFF, 0xFF]);
    mbr[record + 8..record + 12].copy_from_slice(&1u32.to_le_bytes());
    let protective_size = core::cmp::min(last, u64::from(u32::MAX)) as u32;
    mbr[record + 12..record + 16].copy_from_slice(&protective_size.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    dev.write_at(lba_bytes(2)?, &entries)?;
    dev.write_at(lba_bytes(1)?, &primary)?;
    dev.write_at(lba_bytes(backup_entries_start)?, &entries)?;
    dev.write_at(lba_bytes(last)?, &backup)?;
    dev.write_at(0, &mbr)?; // commit point
    Ok(())
}
