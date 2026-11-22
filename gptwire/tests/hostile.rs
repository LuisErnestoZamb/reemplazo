//! Adversarial host tests for `gptwire` — every refusal the parser
//! promises, exercised against crafted in-memory images.
//!
//! Two classes:
//!
//! - **round-trips**: [`gptwire::write`] a layout, [`gptwire::read`]
//!   it back, fields compared — plus name encoding and GUID display;
//! - **corruptions**: take a valid image, break exactly one thing
//!   (signature, CRC, count, bounds, overlap, backup mirror, MBR
//!   garbage…), assert the *exact* [`gptwire::Error`] — so a regression
//!   that turns "refused" into "accepted", or mixes up *which* check
//!   fired, fails here before any QEMU run.
//!
//! The [`Mem`] device is strict: any read/write outside its bytes, or
//! off the 512-byte grid, returns [`gptwire::Error::OutOfRange`]. Every
//! success-path test therefore *also* proves the parser never touched
//! memory outside the image.

use std::cell::RefCell;

use gptwire::{Device, Error, Guid, Partition, TYPE_BASIC_DATA, TYPE_BIOS_GRUB};

/// Test image: 256 sectors (128 KiB) — above the 68-sector floor of
/// `gptwire::write`'s fixed layout, small enough to corrupt freely.
const IMG_SECTORS: u64 = 256;
const IMG_BYTES: usize = IMG_SECTORS as usize * 512;

/// Strict in-memory device: aligned whole sectors only, everything
/// range-checked — the contract the kernel's ATA adapter implements,
/// so a parser bug that escapes the crate's own checks dies here too.
struct Mem(RefCell<Vec<u8>>);

impl Mem {
    fn new(len: usize) -> Self {
        Self(RefCell::new(vec![0u8; len]))
    }

    fn header(&self, lba: u64) -> [u8; 512] {
        let data = self.0.borrow();
        let mut sector = [0u8; 512];
        sector.copy_from_slice(&data[(lba * 512) as usize..(lba * 512 + 512) as usize]);
        sector
    }

    /// Corrupt raw bytes at a byte offset (no CRC repair — used by the
    /// "the CRC itself must catch this" tests).
    fn corrupt(&mut self, offset: usize, bytes: &[u8]) {
        let mut data = self.0.borrow_mut();
        data[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    /// Patch header at `lba`, then **repair its CRC** — so the test
    /// exercises the field check, not the CRC check.
    fn patch_header(&mut self, lba: u64, patch: impl FnOnce(&mut [u8; 512])) {
        let mut sector = self.header(lba);
        patch(&mut sector);
        let mut zeroed = sector;
        zeroed[16..20].fill(0);
        let crc = gptwire::crc32(&zeroed[..92]);
        sector[16..20].copy_from_slice(&crc.to_le_bytes());
        self.corrupt((lba * 512) as usize, &sector);
    }

    /// Recompute the entry-array CRC into both headers (after a test
    /// has edited an entry's bytes), repairing each header's own CRC
    /// too.
    fn repair_entries_crc(&mut self) {
        let primary = self.header(1);
        let num = u32::from_le_bytes(primary[80..84].try_into().expect("slice len")) as usize;
        let crc = gptwire::crc32(&self.0.borrow()[1024..1024 + num * 128]);
        for lba in [1u64, IMG_SECTORS - 1] {
            self.patch_header(lba, |s| s[88..92].copy_from_slice(&crc.to_le_bytes()));
        }
    }
}

impl Device for Mem {
    fn size_bytes(&self) -> u64 {
        self.0.borrow().len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        let data = self.0.borrow();
        if end > data.len() as u64 {
            return Err(Error::OutOfRange);
        }
        buf.copy_from_slice(&data[offset as usize..end as usize]);
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        let mut data = self.0.borrow_mut();
        if end > data.len() as u64 {
            return Err(Error::OutOfRange);
        }
        data[offset as usize..end as usize].copy_from_slice(buf);
        Ok(())
    }
}

/// Read-only device (default `write_at`).
struct ReadOnly;

impl Device for ReadOnly {
    fn size_bytes(&self) -> u64 {
        IMG_BYTES as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        let _ = (offset, buf);
        Err(Error::Read)
    }
}

fn disk_guid() -> Guid {
    Guid::from_bytes([0x99; 16])
}

/// The standard two-partition test layout: bios_grub + basic data,
/// both inside `usable_range(IMG_BYTES)` (= 34..=222).
fn parts() -> Vec<Partition> {
    vec![
        Partition::new(TYPE_BIOS_GRUB, Guid::from_bytes([1; 16]), 34, 100),
        Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([2; 16]), 101, 222)
            .with_name(b"REEMPLAZO")
            .expect("ascii name fits"),
    ]
}

fn valid_image() -> Mem {
    let img = Mem::new(IMG_BYTES);
    gptwire::write(&img, disk_guid(), &parts()).expect("layout writes");
    img
}

// --- CRC32 -------------------------------------------------------------

#[test]
fn crc32_known_check_values() {
    // The standard CRC-32 check value (ISO 3309) and two more vectors
    // cross-checked against zlib — this pins the implementation.
    assert_eq!(gptwire::crc32(b""), 0x0);
    assert_eq!(gptwire::crc32(b"a"), 0xE8B7_BE43);
    assert_eq!(gptwire::crc32(b"abc"), 0x3524_41C2);
    assert_eq!(gptwire::crc32(b"123456789"), 0xCBF4_3926);
}

// --- Round-trips -------------------------------------------------------

#[test]
fn write_then_read_round_trip() {
    let img = valid_image();
    let gpt = gptwire::read(&img).expect("own image parses");
    assert_eq!(gpt.disk_guid, disk_guid());
    assert_eq!(gpt.header_lba, 1);
    assert_eq!(gpt.backup_lba, IMG_SECTORS - 1);
    let (first, last) = gptwire::usable_range(IMG_BYTES as u64).expect("floor met");
    assert_eq!((gpt.first_usable, gpt.last_usable), (first, last));
    let partitions = gpt.partitions();
    assert_eq!(partitions.len(), 2);
    assert_eq!(partitions[0].type_guid, TYPE_BIOS_GRUB);
    assert_eq!((partitions[0].first_lba, partitions[0].last_lba), (34, 100));
    assert_eq!(partitions[1].type_guid, TYPE_BASIC_DATA);
    assert_eq!(
        (partitions[1].first_lba, partitions[1].last_lba),
        (101, 222)
    );
    // Name round-trip: "REEMPLAZO" as UTF-16 units, NUL-padded.
    let expected: Vec<u16> = "REEMPLAZO"
        .bytes()
        .map(u16::from)
        .chain(core::iter::repeat(0))
        .take(36)
        .collect();
    assert_eq!(&partitions[1].name[..], &expected[..]);
    // Unique GUIDs survive.
    assert_eq!(partitions[0].unique_guid, Guid::from_bytes([1; 16]));
    assert_eq!(partitions[1].unique_guid, Guid::from_bytes([2; 16]));
}

#[test]
fn round_trip_four_partitions() {
    let img = Mem::new(IMG_BYTES);
    let four = [
        Partition::new(TYPE_BIOS_GRUB, Guid::from_bytes([1; 16]), 34, 34),
        Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([2; 16]), 35, 100),
        Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([3; 16]), 101, 150),
        Partition::new(TYPE_BIOS_GRUB, Guid::from_bytes([4; 16]), 151, 222),
    ];
    gptwire::write(&img, disk_guid(), &four).expect("four partitions write");
    let gpt = gptwire::read(&img).expect("and parse");
    assert_eq!(gpt.partitions().len(), 4);
    for (got, want) in gpt.partitions().iter().zip(four.iter()) {
        assert_eq!(got, want);
    }
}

#[test]
fn protective_mbr_is_the_expected_shape() {
    let img = valid_image();
    let mbr = img.header(0);
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);
    let record = 446;
    assert_eq!(mbr[record], 0x00); // not bootable
    assert_eq!(mbr[record + 4], 0xEE); // protective type
    let start = u32::from_le_bytes(mbr[record + 8..record + 12].try_into().unwrap());
    let size = u32::from_le_bytes(mbr[record + 12..record + 16].try_into().unwrap());
    assert_eq!(start, 1);
    assert_eq!(size as u64, IMG_SECTORS - 1);
    // The other three records stay empty.
    for i in 1..4 {
        let r = 446 + 16 * i;
        assert_eq!(mbr[r + 4], 0x00);
    }
}

// --- Protective MBR ----------------------------------------------------

#[test]
fn read_rejects_blank_disk() {
    let img = Mem::new(IMG_BYTES);
    assert_eq!(gptwire::read(&img), Err(Error::BadProtectiveMbr));
}

#[test]
fn read_rejects_bad_mbr_signature() {
    let mut img = valid_image();
    img.corrupt(510, &[0x00, 0x00]);
    assert_eq!(gptwire::read(&img), Err(Error::BadProtectiveMbr));
}

#[test]
fn read_rejects_missing_protective_type() {
    let mut img = valid_image();
    img.corrupt(450, &[0x83]); // Linux type instead of 0xEE
    assert_eq!(gptwire::read(&img), Err(Error::BadProtectiveMbr));
}

#[test]
fn read_rejects_zero_size_protective() {
    let mut img = valid_image();
    img.corrupt(458, &[0, 0, 0, 0]); // size LBA = 0
    assert_eq!(gptwire::read(&img), Err(Error::BadProtectiveMbr));
}

#[test]
fn read_rejects_protective_start_lba_not_one() {
    // The protective record must start at LBA1 (UEFI spec); a record
    // pointing elsewhere is refused.
    let mut img = valid_image();
    img.corrupt(454, &[2, 0, 0, 0]);
    assert_eq!(gptwire::read(&img), Err(Error::BadProtectiveMbr));
}

#[test]
fn read_accepts_mbr_boot_code_and_chs_garbage() {
    // The boot-code area and the legacy CHS bytes are unused for a
    // protective MBR: garbage there must NOT cause a refusal (only
    // type/LBA/size are validated).
    let mut img = valid_image();
    let junk: Vec<u8> = (0..446).map(|i| (i * 7 + 3) as u8).collect();
    img.corrupt(0, &junk);
    assert!(gptwire::read(&img).is_ok());
}

// --- Header ------------------------------------------------------------

#[test]
fn read_rejects_bad_signature() {
    let mut img = valid_image();
    img.corrupt(512, b"NOT A PT");
    assert_eq!(gptwire::read(&img), Err(Error::BadSignature));
}

#[test]
fn read_rejects_bad_revision() {
    let mut img = valid_image();
    img.corrupt(512 + 8, &2u32.to_le_bytes());
    assert_eq!(gptwire::read(&img), Err(Error::BadRevision));
}

#[test]
fn read_rejects_header_size_outside_bounds() {
    let mut small = valid_image();
    small.corrupt(512 + 12, &91u16.to_le_bytes());
    assert_eq!(gptwire::read(&small), Err(Error::BadHeaderSize));

    let mut large = valid_image();
    large.corrupt(512 + 12, &513u16.to_le_bytes());
    assert_eq!(gptwire::read(&large), Err(Error::BadHeaderSize));
}

#[test]
fn read_rejects_header_crc_mismatch() {
    let mut img = valid_image();
    // Flip one bit of `current_lba` without repairing the CRC: the
    // CRC check must fire (before the field checks).
    let mut sector = img.header(1);
    sector[24] ^= 0x01;
    img.corrupt(512, &sector);
    assert_eq!(gptwire::read(&img), Err(Error::BadHeaderCrc));
}

#[test]
fn read_rejects_reserved_word_nonzero() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[20] = 0xFF);
    assert_eq!(gptwire::read(&img), Err(Error::BadReserved));
}

#[test]
fn read_rejects_current_lba_mismatch() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[24..32].copy_from_slice(&2u64.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadCurrentLba));
}

#[test]
fn read_rejects_backup_lba_field_mismatch() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[32..40].copy_from_slice(&7u64.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadBackupLba));
}

#[test]
fn read_rejects_inverted_usable_range() {
    let mut img = valid_image();
    img.patch_header(1, |s| {
        s[40..48].copy_from_slice(&200u64.to_le_bytes()); // first > last
        s[48..56].copy_from_slice(&100u64.to_le_bytes());
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadUsableRange));
}

#[test]
fn read_rejects_usable_range_past_device() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[48..56].copy_from_slice(&IMG_SECTORS.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadUsableRange));
}

// --- Entry array -------------------------------------------------------

#[test]
fn read_rejects_absurd_entry_count() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[80..84].copy_from_slice(&u32::MAX.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_entry_count_over_cap() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[80..84].copy_from_slice(&129u32.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_zero_entry_count() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[80..84].copy_from_slice(&0u32.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_entry_size_other_than_128() {
    for size in [0u32, 64, 256, 512] {
        let mut img = valid_image();
        img.patch_header(1, |s| s[84..88].copy_from_slice(&size.to_le_bytes()));
        assert_eq!(
            gptwire::read(&img),
            Err(Error::BadEntryArray),
            "size {size}"
        );
    }
}

#[test]
fn read_rejects_entries_start_below_lba2() {
    let mut img = valid_image();
    img.patch_header(1, |s| s[72..80].copy_from_slice(&0u64.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_entries_reaching_past_device() {
    // Entries start at 1 EiB: the LBA→byte multiply fits in u64 but
    // the range check must refuse it before any read is issued.
    let mut img = valid_image();
    img.patch_header(1, |s| {
        s[72..80].copy_from_slice(&(1u64 << 40).to_le_bytes())
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_entries_inside_usable_range() {
    // Shrink first_usable so it lands *inside* the primary array.
    let mut img = valid_image();
    img.patch_header(1, |s| s[40..48].copy_from_slice(&10u64.to_le_bytes()));
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_entry_array_crc_mismatch() {
    let mut img = valid_image();
    // Flip a byte inside the primary entry array — headers untouched,
    // so the array's own CRC must catch it.
    img.corrupt(1024 + 40, &[0xEE]); // inside entry 0's first-LBA field
    assert_eq!(gptwire::read(&img), Err(Error::BadEntriesCrc));
}

// --- Partitions --------------------------------------------------------

#[test]
fn read_rejects_partition_past_usable_range() {
    let mut img = valid_image();
    // Entry 1's last LBA beyond last_usable (222).
    img.corrupt(1024 + 128 + 40, &(300u64).to_le_bytes());
    img.repair_entries_crc();
    assert_eq!(gptwire::read(&img), Err(Error::BadPartition));
}

#[test]
fn read_rejects_inverted_partition_range() {
    let mut img = valid_image();
    // Entry 0 is 34..100; first = 101 makes it inverted.
    img.corrupt(1024 + 32, &(101u64).to_le_bytes());
    img.repair_entries_crc();
    assert_eq!(gptwire::read(&img), Err(Error::BadPartition));
}

#[test]
fn read_rejects_overlapping_partitions() {
    let mut img = valid_image();
    // Pull entry 1's start back into entry 0's range (100 >= 34).
    img.corrupt(1024 + 128 + 32, &(100u64).to_le_bytes());
    img.repair_entries_crc();
    assert_eq!(gptwire::read(&img), Err(Error::Overlap));
}

#[test]
fn read_ignores_unused_slots_with_garbage_tail() {
    // A zero type marks an unused slot; the rest of the slot is not
    // defined by the format and must not be parsed (documented
    // leniency). Slot 2 (offset 1024+256) gets a zeroed type with a
    // garbage tail — corrupted in the backup mirror too, so the two
    // arrays still agree and the mirror checks stay green.
    let mut img = valid_image();
    let backup_start = ((IMG_SECTORS - 1 - 32) * 512) as usize;
    let junk: Vec<u8> = (0..112).map(|i| (0xA0 + i) as u8).collect();
    for base in [1024, backup_start] {
        img.corrupt(base + 256, &junk); // type GUID bytes stay whatever they were…
        img.corrupt(base + 256, &[0; 16]); // …then zeroed: unused slot
    }
    img.repair_entries_crc();
    let gpt = gptwire::read(&img).expect("garbage tail ignored");
    assert_eq!(gpt.partitions().len(), 2);
}

// --- Backup mirror -----------------------------------------------------

#[test]
fn read_rejects_backup_signature() {
    let mut img = valid_image();
    let last = (IMG_SECTORS - 1) * 512;
    img.corrupt(last as usize, b"GARBAGE");
    assert_eq!(gptwire::read(&img), Err(Error::BadSignature));
}

#[test]
fn read_rejects_backup_current_lba_mismatch() {
    let mut img = valid_image();
    img.patch_header(IMG_SECTORS - 1, |s| {
        s[24..32].copy_from_slice(&5u64.to_le_bytes())
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadCurrentLba));
}

#[test]
fn read_rejects_backup_field_disagreeing_with_primary() {
    let mut img = valid_image();
    img.patch_header(IMG_SECTORS - 1, |s| {
        s[40..48].copy_from_slice(&50u64.to_le_bytes()); // first_usable drift
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadBackup));
}

#[test]
fn read_rejects_backup_offset_mismatch() {
    // Shift the backup entry array one sector earlier: it would sit
    // inside the usable range / end before the backup header — either
    // way the mirror layout is wrong.
    let mut img = valid_image();
    img.patch_header(IMG_SECTORS - 1, |s| {
        let shifted = IMG_SECTORS - 1 - 31;
        s[72..80].copy_from_slice(&shifted.to_le_bytes());
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadEntryArray));
}

#[test]
fn read_rejects_corrupt_backup_array_bytes() {
    // Every header field still matches; only the backup array's *bytes*
    // differ from the primary — the byte-level re-checksum must fail.
    let mut img = valid_image();
    let backup_start = (IMG_SECTORS - 1 - 32) * 512;
    img.corrupt(backup_start as usize + 40, &[0x5A]);
    assert_eq!(gptwire::read(&img), Err(Error::BadBackup));
}

#[test]
fn read_rejects_backup_lba_field_not_one() {
    let mut img = valid_image();
    img.patch_header(IMG_SECTORS - 1, |s| {
        s[32..40].copy_from_slice(&9u64.to_le_bytes())
    });
    assert_eq!(gptwire::read(&img), Err(Error::BadBackupLba));
}

// --- Device-bound refusals ---------------------------------------------

#[test]
fn read_rejects_truncated_device() {
    // A truncated image cannot keep a self-consistent header: the
    // surviving `backup_lba` (255) disagrees with the real device end,
    // so the size cross-check refuses it — the parser never gets to a
    // read that would run off the image. (Structurally, every read it
    // *does* issue is bounded by these cross-checks first: the
    // entry-array region checks pin the array inside
    // `first_usable ≤ last_usable < total`, and the strict [`Mem`]
    // device proves that bound on every success-path test.)
    let img = valid_image();
    let mut truncated = Mem::new(20 * 512);
    {
        let mut data = truncated.0.borrow_mut();
        data.copy_from_slice(&img.0.borrow()[..20 * 512]);
    }
    assert_eq!(gptwire::read(&truncated), Err(Error::BadBackupLba));

    // Even patching `backup_lba` to match the tiny device leaves the
    // usable range (last_usable 222 ≥ total 20) disagreeing — still a
    // refusal, still no out-of-bounds read.
    truncated.patch_header(1, |s| s[32..40].copy_from_slice(&19u64.to_le_bytes()));
    assert_eq!(gptwire::read(&truncated), Err(Error::BadUsableRange));
}

#[test]
fn read_rejects_device_below_arithmetic_floor() {
    assert_eq!(gptwire::read(&Mem::new(100)), Err(Error::TooSmall));
    assert_eq!(gptwire::read(&Mem::new(5 * 512)), Err(Error::TooSmall));
    // Exactly at the floor: MBR + header parse, then the header's
    // backup_lba disagrees with the tiny device (size cross-check).
    let img = valid_image();
    let six = Mem::new(6 * 512);
    {
        let mut data = six.0.borrow_mut();
        data.copy_from_slice(&img.0.borrow()[..6 * 512]);
    }
    assert_eq!(gptwire::read(&six), Err(Error::BadBackupLba));
}

#[test]
fn read_rejects_device_not_sector_multiple() {
    assert_eq!(gptwire::read(&Mem::new(68 * 512 + 1)), Err(Error::TooSmall));
}

// --- Write refusals ----------------------------------------------------

#[test]
fn usable_range_floor() {
    assert_eq!(gptwire::usable_range(67 * 512), None);
    assert_eq!(gptwire::usable_range(68 * 512), Some((34, 34)));
    assert_eq!(gptwire::usable_range(68 * 512 + 1), None);
}

#[test]
fn write_rejects_too_small_device() {
    let img = Mem::new(67 * 512);
    assert_eq!(
        gptwire::write(&img, disk_guid(), &parts()),
        Err(Error::TooSmall)
    );
}

#[test]
fn write_rejects_overlapping_layout() {
    let img = Mem::new(IMG_BYTES);
    let overlap = [
        Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([1; 16]), 34, 100),
        Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([2; 16]), 100, 222),
    ];
    assert_eq!(
        gptwire::write(&img, disk_guid(), &overlap),
        Err(Error::Overlap)
    );
}

#[test]
fn write_rejects_partition_outside_usable() {
    let img = Mem::new(IMG_BYTES);
    let too_far = [Partition::new(
        TYPE_BASIC_DATA,
        Guid::from_bytes([1; 16]),
        34,
        9999,
    )];
    assert_eq!(
        gptwire::write(&img, disk_guid(), &too_far),
        Err(Error::BadPartition)
    );
    let inverted = [Partition::new(
        TYPE_BASIC_DATA,
        Guid::from_bytes([1; 16]),
        200,
        100,
    )];
    assert_eq!(
        gptwire::write(&img, disk_guid(), &inverted),
        Err(Error::BadPartition)
    );
}

#[test]
fn write_rejects_empty_partition_and_empty_list() {
    let img = Mem::new(IMG_BYTES);
    assert_eq!(
        gptwire::write(&img, disk_guid(), &[]),
        Err(Error::BadPartition)
    );
    let empty_slot = [Partition::new(Guid::ZERO, Guid::ZERO, 34, 100)];
    assert_eq!(
        gptwire::write(&img, disk_guid(), &empty_slot),
        Err(Error::BadPartition)
    );
}

#[test]
fn write_rejects_too_many_partitions() {
    let img = Mem::new(IMG_BYTES);
    let many: Vec<Partition> = (0..129)
        .map(|i| {
            let i = i as u64;
            Partition::new(
                TYPE_BASIC_DATA,
                Guid::from_bytes([i as u8; 16]),
                34 + i,
                34 + i,
            )
        })
        .collect();
    assert_eq!(
        gptwire::write(&img, disk_guid(), &many),
        Err(Error::TooManyPartitions)
    );
}

#[test]
fn write_refuses_readonly_device() {
    let readonly = ReadOnly;
    assert_eq!(
        gptwire::write(&readonly, disk_guid(), &parts()),
        Err(Error::ReadOnly)
    );
}

// --- Names & GUIDs -----------------------------------------------------

#[test]
fn name_refuses_overlong_and_non_ascii() {
    let p = Partition::new(TYPE_BASIC_DATA, Guid::from_bytes([1; 16]), 34, 100);
    assert_eq!(p.with_name(&[b'A'; 37]), Err(Error::Name));
    assert!(p.with_name(b"ok").is_ok());
    assert_eq!(p.with_name(&[0x80]), Err(Error::Name));
    assert_eq!(p.with_name(b"caf\xC3\xA9"), Err(Error::Name)); // UTF-8 multibyte not ASCII
}

#[test]
fn guid_debug_is_canonical_text() {
    // Mixed-endian: bytes 0..4 are Data1 (LE), 4..6 Data2, 6..8 Data3,
    // 8..16 Data4 as-is.
    let guid = Guid::from_bytes([
        0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6F, 0x6E, 0x74, 0x4E, 0x65, 0x65, 0x64, 0x45, 0x46,
        0x49,
    ]);
    assert_eq!(format!("{guid:?}"), "21686148-6449-6e6f-744e-656564454649");
    // Which is exactly docs/installer.md §3.2's bios_grub GUID — the
    // constant's byte order is pinned by this test.
    assert_eq!(TYPE_BIOS_GRUB, guid);
}
