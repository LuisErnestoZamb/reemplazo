//! Adversarial and round-trip tests for the read-only FAT16 reader the
//! kernel's boot proof (`FAT_OK`) runs against a real disk.
//!
//! Every test drives the reader through [`Strict`], a block adapter that
//! mirrors the kernel's ATA one exactly (whole 512-byte sectors only,
//! anything outside the device is `OutOfRange`): if the reader ever asked
//! for a sector past the end of the image — overrunning the root region,
//! the FAT, or the data area — the test would fail on the adapter's error
//! instead of quietly reading zeros.

use fat::{BlockDevice, Error, Fat16};

// --- Fixed test geometry -------------------------------------------------

const SECTOR: usize = 512;
/// 2 MiB + a little — small enough to build in every test, large enough
/// for a FAT16 cluster window (4127 clusters ≥ 4085).
const TOTAL: usize = 4224;
const RESERVED: u32 = 1;
const FAT_SECTORS: u32 = 32;
const ROOT_SECTORS: u32 = 32;
const ROOT_ENTRIES: u32 = 512;
const ROOT_START: u32 = RESERVED + 2 * FAT_SECTORS; // 65
const DATA_START: u32 = ROOT_START + ROOT_SECTORS; // 97
const CLUSTERS: u32 = TOTAL as u32 - DATA_START; // 8095 (sectors/cluster = 1)

/// `/README.TXT` — byte-identical to what `xtask write_disk_image` puts
/// in the installer smoke's disk and what `kernel/src/fs` asserts.
const README: &[u8] = b"reemplazo filesystem ok\n";
const LONG_NAME: &str = "SuperLongFileName.txt";
const LONG_CONTENT: &[u8] = b"long file content!";

// --- The block adapter under test ---------------------------------------

/// A read-only in-memory device with the kernel ATA adapter's contract:
/// 512-byte-aligned, whole-sector reads only, hard refusal outside the
/// device. It also mirrors the ATA driver's *reported capacity* (a whole
/// number of sectors), which is what `mount` bounds its volume against.
struct Strict<'a> {
    data: &'a [u8],
}

impl BlockDevice for Strict<'_> {
    fn size_bytes(&self) -> u64 {
        self.data.len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        if end > self.data.len() as u64 {
            return Err(Error::OutOfRange);
        }
        let start = offset as usize;
        buf.copy_from_slice(&self.data[start..start + buf.len()]);
        Ok(())
    }
}

/// Mount `img` through [`Strict`] and return the refusal reason.
fn mount_err(img: &[u8]) -> Error {
    let dev = Strict { data: img };
    match Fat16::mount(&dev) {
        Ok(_) => panic!("mount unexpectedly succeeded"),
        Err(e) => e,
    }
}

// --- Image construction ---------------------------------------------------

fn put16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// FAT entry `cluster` in *both* copies (the reader uses FAT #0; keeping
/// them equal is what a formatter does).
fn fat_set(img: &mut [u8], cluster: u32, value: u16) {
    let byte = cluster as usize * 2;
    for copy in 0..2 {
        let base = (RESERVED as usize + copy * FAT_SECTORS as usize) * SECTOR + byte;
        put16(img, base, value);
    }
}

/// Directory-entry slot `slot` of the fixed root region.
fn root_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = ROOT_START as usize * SECTOR + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

/// Directory-entry slot `slot` of the subdirectory living at cluster 4.
fn sub_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = DATA_START as usize * SECTOR + 2 * SECTOR + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

/// Byte offset of cluster `n` (the data region starts at cluster 2).
fn cluster_off(n: u32) -> usize {
    DATA_START as usize * SECTOR + (n as usize - 2) * SECTOR
}

/// Classic 8.3 directory entry.
fn entry(name8: &[u8; 8], ext3: &[u8; 3], attr: u8, cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..8].copy_from_slice(name8);
    e[8..11].copy_from_slice(ext3);
    e[11] = attr;
    put16(&mut e, 20, 0); // FAT16: the high cluster word must be zero
    put16(&mut e, 26, cluster);
    put32(&mut e, 28, size);
    e
}

/// The FAT spec's LFN checksum over an 11-byte 8.3 name.
fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &c| {
        (((sum & 1) << 7) | (sum >> 1)).wrapping_add(c)
    })
}

/// One LFN directory entry holding entries `seq` (1-based) of `units`,
/// flagged 0x40 when `seq` is the chain's last entry.
fn lfn_entry(units: &[u16], seq: u8, last: bool, sum: u8) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = seq | if last { 0x40 } else { 0 };
    e[11] = 0x0F; // READ_ONLY|HIDDEN|SYSTEM|VOLUME marks an LFN part
    e[13] = sum;
    for k in 0..13 {
        let i = usize::from(seq - 1) * 13 + k;
        let unit = if i < units.len() {
            units[i]
        } else if i == units.len() {
            0 // terminator right after the name
        } else {
            0xFFFF // padding
        };
        let from = match k {
            0..=4 => 1 + k * 2,
            5..=10 => 14 + (k - 5) * 2,
            _ => 28 + (k - 11) * 2,
        };
        e[from..from + 2].copy_from_slice(&unit.to_le_bytes());
    }
    e
}

/// UTF-16 code units of `s` (test data: ASCII only, no surrogates).
fn units(s: &str) -> Vec<u16> {
    s.chars().map(|c| c as u16).collect()
}

/// A well-formed 4 MiB FAT16 volume with:
/// `/README.TXT` (24 B, cluster 2) · `/SuperLongFileName.txt` (LFN over
/// `SUPERL~1.TXT`, 18 B, cluster 3) · `/SUB/CHILD.BIN` (40 B, cluster 5)
/// · `/EMPTY.TXT` (0 B, no cluster) · `/EXACT.BIN` (512 B = exactly one
/// cluster, cluster 6).
fn image() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL * SECTOR];

    // Boot sector (scoped: `boot` mutably borrows `img`).
    {
        let b = &mut img[0..SECTOR];
        b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MSDOS5.0");
        put16(b, 11, 512); // bytes/sector
        b[13] = 1; // sectors/cluster
        put16(b, 14, RESERVED as u16);
        b[16] = 2; // FATs
        put16(b, 17, ROOT_ENTRIES as u16);
        put16(b, 19, 0); // total16: this volume uses total32
        b[21] = 0xF8; // media
        put16(b, 22, FAT_SECTORS as u16);
        put16(b, 24, 63); // sectors/track
        put16(b, 26, 255); // heads
        put32(b, 28, 0); // hidden
        put32(b, 32, TOTAL as u32);
        b[36] = 0x80;
        b[38] = 0x29; // boot signature → the next four fields are present
        put32(b, 39, 0x2026_1121);
        b[43..54].copy_from_slice(b"REEMPLAZO  ");
        b[54..62].copy_from_slice(b"FAT16   ");
        b[510] = 0x55;
        b[511] = 0xAA;
    }

    // FAT: media/EOC bookkeeping plus one closed chain per file.
    fat_set(&mut img, 0, 0xFFF8);
    fat_set(&mut img, 1, 0xFFFF);
    for cluster in 2..=6 {
        fat_set(&mut img, cluster, 0xFFFF);
    }

    // Root directory.
    root_slot(
        &mut img,
        0,
        &entry(b"README  ", b"TXT", 0x20, 2, README.len() as u32),
    );
    let sum = checksum(b"SUPERL~1TXT");
    let long_units = units(LONG_NAME);
    root_slot(&mut img, 1, &lfn_entry(&long_units, 2, true, sum));
    root_slot(&mut img, 2, &lfn_entry(&long_units, 1, false, sum));
    root_slot(
        &mut img,
        3,
        &entry(b"SUPERL~1", b"TXT", 0x20, 3, LONG_CONTENT.len() as u32),
    );
    root_slot(&mut img, 4, &entry(b"SUB     ", b"   ", 0x10, 4, 0));
    root_slot(&mut img, 5, &entry(b"EMPTY   ", b"TXT", 0x20, 0, 0));
    root_slot(&mut img, 6, &entry(b"EXACT   ", b"BIN", 0x20, 6, 512));

    // Data region.
    let (c2, c3) = (cluster_off(2), cluster_off(3));
    img[c2..c2 + README.len()].copy_from_slice(README);
    img[c3..c3 + LONG_CONTENT.len()].copy_from_slice(LONG_CONTENT);
    sub_slot(&mut img, 0, &entry(b"CHILD   ", b"BIN", 0x20, 5, 40));
    sub_slot(&mut img, 1, &[0u8; 32]); // 0x00 = end of directory
    img[cluster_off(5)..cluster_off(5) + 40].fill(0xAB);
    img[cluster_off(6)..cluster_off(6) + 512].fill(0xCD);
    img
}

/// The reader under test. The [`Strict`] device is leaked so the mount
/// can outlive this helper — host tests only (`std` is available), the
/// same outliving trick `mbi`'s suite uses.
fn mounted<'a>(img: &'a [u8]) -> Fat16<'a, Strict<'a>> {
    let dev: &'a Strict<'a> = Box::leak(Box::new(Strict { data: img }));
    Fat16::mount(dev).expect("well-formed image mounts")
}

// --- Round trip (the happy path is a test too) ---------------------------

#[test]
fn readmes_round_trips_byte_for_byte() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    let n = fs.read_file("/README.TXT", &mut buf).expect("read");
    assert_eq!(&buf[..n], README);
    assert_eq!(n, 24);
}

#[test]
fn lookup_is_ascii_case_insensitive() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/readme.txt", &mut buf), Ok(24));
    assert_eq!(fs.read_file("/ReAdMe.TxT", &mut buf), Ok(24));
}

#[test]
fn long_name_is_assembled_and_matched() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    let n = fs
        .read_file(&format!("/{LONG_NAME}"), &mut buf)
        .expect("LFN lookup");
    assert_eq!(&buf[..n], LONG_CONTENT);
    // The 8.3 alias still works: an LFN is additive, never a replacement.
    let n = fs.read_file("/SUPERL~1.TXT", &mut buf).expect("8.3 alias");
    assert_eq!(&buf[..n], LONG_CONTENT);
}

#[test]
fn subdirectory_file_resolves_through_the_chain() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    let n = fs.read_file("/SUB/CHILD.BIN", &mut buf).expect("read");
    assert_eq!(n, 40);
    assert!(buf[..n].iter().all(|&b| b == 0xAB));
}

#[test]
fn empty_file_reads_zero_bytes_without_touching_a_chain() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/EMPTY.TXT", &mut buf), Ok(0));
}

#[test]
fn file_exactly_one_cluster_long() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 512];
    let n = fs.read_file("/EXACT.BIN", &mut buf).expect("read");
    assert_eq!(n, 512);
    assert!(buf.iter().all(|&b| b == 0xCD));
}

#[test]
fn file_larger_than_one_cluster_spans_the_chain() {
    let mut img = image();
    // Grow EXACT.BIN to 700 bytes: two clusters, FAT[6] must point at 7.
    put32(&mut img, ROOT_START as usize * SECTOR + 6 * 32 + 28, 700);
    fat_set(&mut img, 6, 7);
    fat_set(&mut img, 7, 0xFFFF);
    img[cluster_off(6)..cluster_off(6) + 512].fill(0x11);
    img[cluster_off(7)..cluster_off(7) + 512].fill(0x22);

    let fs = mounted(&img);
    let mut buf = [0u8; 700];
    let n = fs.read_file("/EXACT.BIN", &mut buf).expect("read");
    assert_eq!(n, 700);
    assert!(buf[..512].iter().all(|&b| b == 0x11));
    assert!(buf[512..].iter().all(|&b| b == 0x22));
}

// --- Boot-sector validation ---------------------------------------------

#[test]
fn truncated_boot_sector_is_refused() {
    assert_eq!(mount_err(&[]), Error::TooSmall);
    let tiny = vec![0u8; 256];
    assert_eq!(mount_err(&tiny), Error::TooSmall);
    let short = vec![0u8; 511];
    assert_eq!(mount_err(&short), Error::TooSmall);
}

#[test]
fn bogus_bytes_per_sector_is_refused() {
    for bps in [0u16, 1, 100, 256, 511, 513, 8192, 0xFFFF] {
        let mut img = image();
        put16(&mut img, 11, bps);
        assert_eq!(mount_err(&img), Error::BadBytesPerSector, "bps={bps}");
    }
}

#[test]
fn zero_and_non_power_of_two_sectors_per_cluster_are_refused() {
    for spc in [0u8, 3, 5, 6, 7, 9, 100] {
        let mut img = image();
        img[13] = spc;
        assert_eq!(mount_err(&img), Error::BadSectorsPerCluster, "spc={spc}");
    }
}

#[test]
fn cluster_larger_than_32_kib_is_refused() {
    // 128 sectors × 512 B = 64 KiB: a power of two, but out of spec.
    let mut img = image();
    img[13] = 128;
    assert_eq!(mount_err(&img), Error::BadSectorsPerCluster);
}

#[test]
fn missing_55aa_signature_is_refused() {
    let mut img = image();
    img[510] = 0;
    img[511] = 0;
    assert_eq!(mount_err(&img), Error::BadSignature);

    let mut img = image();
    img[510] = 0xAA;
    img[511] = 0x55; // byte-swapped
    assert_eq!(mount_err(&img), Error::BadSignature);
}

#[test]
fn signature_must_close_the_second_half_when_bps_is_1024() {
    // With bps = 1024 the signature lives at 1022, not 510 — a boot
    // sector copied from a 512-byte volume must not pass.
    let mut img = vec![0u8; TOTAL * SECTOR];
    img[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
    put16(&mut img, 11, 1024);
    img[13] = 1;
    put16(&mut img, 14, RESERVED as u16);
    img[16] = 2;
    put16(&mut img, 17, ROOT_ENTRIES as u16);
    img[21] = 0xF8;
    put16(&mut img, 22, FAT_SECTORS as u16);
    put32(&mut img, 32, 4096);
    img[510] = 0x55;
    img[511] = 0xAA; // signature in the wrong place
    assert_eq!(mount_err(&img), Error::BadSignature);
}

#[test]
fn bad_jump_instruction_is_refused() {
    for first in [0x00u8, 0x90, 0x55, 0xFF] {
        let mut img = image();
        img[0] = first;
        assert_eq!(mount_err(&img), Error::BadJump, "byte0={first:#04x}");
    }
}

#[test]
fn fat_count_outside_one_or_two_is_refused() {
    for count in [0u8, 3, 255] {
        let mut img = image();
        img[16] = count;
        assert_eq!(mount_err(&img), Error::BadFatCount, "fats={count}");
    }
}

#[test]
fn zero_reserved_sectors_is_refused() {
    let mut img = image();
    put16(&mut img, 14, 0);
    assert_eq!(mount_err(&img), Error::BadReserved);
}

#[test]
fn zero_root_entries_is_refused() {
    let mut img = image();
    put16(&mut img, 17, 0);
    assert_eq!(mount_err(&img), Error::BadRootEntries);
}

#[test]
fn zero_total_sectors_is_refused() {
    let mut img = image();
    put16(&mut img, 19, 0);
    put32(&mut img, 32, 0);
    assert_eq!(mount_err(&img), Error::BadTotalSectors);
}

#[test]
fn implausible_media_descriptor_is_refused() {
    for media in [0x00u8, 0x20, 0xEF] {
        let mut img = image();
        img[21] = media;
        assert_eq!(mount_err(&img), Error::BadMedia, "media={media:#04x}");
    }
}

#[test]
fn first_fat_entry_must_mirror_the_media_descriptor() {
    let mut img = image();
    fat_set(&mut img, 0, 0xFFF0); // low byte 0xF0 ≠ media 0xF8
    assert_eq!(mount_err(&img), Error::BadMedia);
}

#[test]
fn fat32_volume_is_refused() {
    // FATsz16 == 0 is how a FAT32 volume marks itself.
    let mut img = image();
    put16(&mut img, 22, 0);
    assert_eq!(mount_err(&img), Error::NotFat16);
}

#[test]
fn too_few_clusters_to_be_fat16_is_refused() {
    // Declare a 1 MiB volume: ~1960 clusters is a FAT12 volume, and
    // FAT12 parsing is out of scope for this read-only v1.
    let mut img = image();
    put32(&mut img, 32, 2000);
    assert_eq!(mount_err(&img), Error::NotFat16);
}

#[test]
fn volume_larger_than_the_device_is_refused() {
    let mut img = image();
    put32(&mut img, 32, (TOTAL * 2) as u32); // BPB claims 8 MiB
    assert_eq!(mount_err(&img), Error::OutOfRange);
}

#[test]
fn device_smaller_than_the_declared_volume_is_refused() {
    let mut img = image();
    img.truncate(96 * SECTOR); // not even boot + FATs + root fit
    assert_eq!(mount_err(&img), Error::OutOfRange);
}

#[test]
fn structures_overrunning_the_declared_total_are_refused() {
    // total = 90 sectors < root_start(65) + root(32) = 97.
    let mut img = image();
    put32(&mut img, 32, 90);
    assert_eq!(mount_err(&img), Error::Truncated);
}

#[test]
fn undersized_fat_is_refused() {
    // FS2 hardening: each FAT copy must hold (clusters + 2) × 2 bytes.
    // At FATsz16 = 16 the volume has 4159 clusters → 4161 entries ×
    // 2 = 8322 B > 16 sectors (8192 B), so a high cluster's FAT entry
    // would spill into the next FAT copy or the root directory.
    let mut img = image();
    put16(&mut img, 22, 16);
    assert_eq!(mount_err(&img), Error::BadFatSize);
}

// --- Bounds arithmetic ----------------------------------------------------

#[test]
fn checked_end_refuses_overflow_and_out_of_range() {
    assert_eq!(fat::checked_end(1024, 0, 1024), Ok(1024));
    assert_eq!(fat::checked_end(1024, 512, 512), Ok(1024));
    assert_eq!(fat::checked_end(1024, 513, 511), Ok(1024));
    assert_eq!(fat::checked_end(1024, 513, 512), Err(Error::OutOfRange));
    assert_eq!(fat::checked_end(1024, 1024, 1), Err(Error::OutOfRange));
    assert_eq!(fat::checked_end(1024, u64::MAX, 1), Err(Error::OutOfRange));
    assert_eq!(
        fat::checked_end(u64::MAX - 1, u64::MAX, 1),
        Err(Error::OutOfRange)
    );
    assert_eq!(
        fat::checked_end(1024, 0, usize::MAX),
        Err(Error::OutOfRange)
    );
}

// --- Cluster-chain hostility ---------------------------------------------

#[test]
fn cyclic_fat_fails_instead_of_hanging() {
    let mut img = image();
    // README claims 4096 bytes (8 clusters) while FAT[2] ⇄ FAT[3] loop.
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 4096);
    fat_set(&mut img, 2, 3);
    fat_set(&mut img, 3, 2);

    let fs = mounted(&img);
    let mut buf = [0u8; 4096];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn self_referential_cluster_fails() {
    let mut img = image();
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 1024);
    fat_set(&mut img, 2, 2);

    let fs = mounted(&img);
    let mut buf = [0u8; 1024];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn chain_pointing_beyond_the_data_region_fails() {
    let mut img = image();
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 1024);
    // One past the last valid cluster index.
    fat_set(&mut img, 2, (CLUSTERS + 2) as u16);

    let fs = mounted(&img);
    let mut buf = [0u8; 1024];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn file_first_cluster_beyond_the_data_region_fails() {
    let mut img = image();
    put16(&mut img, ROOT_START as usize * SECTOR + 26, 0xFFFF);

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn size_lying_beyond_the_chain_fails() {
    let mut img = image();
    // 1000 bytes need two clusters; the chain closes after one.
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 1000);

    let fs = mounted(&img);
    let mut buf = [0u8; 1000];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn free_cluster_inside_a_chain_fails() {
    let mut img = image();
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 1024);
    fat_set(&mut img, 2, 7); // legal hop…
    fat_set(&mut img, 7, 0x0000); // …into free space

    let fs = mounted(&img);
    let mut buf = [0u8; 1024];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn bad_cluster_inside_a_chain_fails() {
    let mut img = image();
    put32(&mut img, ROOT_START as usize * SECTOR + 28, 1024);
    fat_set(&mut img, 2, 0xFFF7);

    let fs = mounted(&img);
    let mut buf = [0u8; 1024];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::BadChain));
}

#[test]
fn buffer_smaller_than_the_file_is_refused_before_any_walk() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 10];
    assert_eq!(
        fs.read_file("/README.TXT", &mut buf),
        Err(Error::BufferTooSmall)
    );
}

// --- Directory hostility --------------------------------------------------

#[test]
fn scan_never_leaves_the_root_region() {
    // Move README's entry to slot 512 — one past the region. A reader
    // that walked on would find it in the *data* region (and `Strict`
    // would happily serve that sector); ours must not even try.
    let mut img = image();
    let off = ROOT_START as usize * SECTOR;
    let mut moved = [0u8; 32];
    moved.copy_from_slice(&img[off..off + 32]);
    img[off..off + 32].fill(0);
    let past = off + 512 * 32;
    img[past..past + 32].copy_from_slice(&moved);

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::NotFound));
}

#[test]
fn deleted_entry_is_skipped() {
    let mut img = image();
    img[ROOT_START as usize * SECTOR] = 0xE5;
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Err(Error::NotFound));
}

#[test]
fn directory_entry_with_fat32_high_cluster_word_is_refused() {
    let mut img = image();
    put16(&mut img, ROOT_START as usize * SECTOR + 20, 1);
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file("/README.TXT", &mut buf),
        Err(Error::BadDirectory)
    );
}

#[test]
fn cyclic_subdirectory_chain_fails_instead_of_hanging() {
    // Fill SUB's cluster with entries that match nothing (and carry no
    // 0x00 end marker), then close its chain into a self-loop: the scan
    // must exhaust the hop budget rather than spin.
    let mut img = image();
    let sub = DATA_START as usize * SECTOR + 2 * SECTOR;
    img[sub..sub + SECTOR].fill(0xFF);
    fat_set(&mut img, 4, 4);

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file("/SUB/CHILD.BIN", &mut buf),
        Err(Error::BadChain)
    );
}

#[test]
fn subdirectory_must_be_a_directory_on_the_way() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file("/README.TXT/CHILD.BIN", &mut buf),
        Err(Error::NotAFile)
    );
}

#[test]
fn directory_is_not_a_file() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(fs.read_file("/SUB", &mut buf), Err(Error::NotAFile));
    assert_eq!(fs.read_file("/SUB/", &mut buf), Err(Error::NotAFile));
}

// --- LFN hostility --------------------------------------------------------

#[test]
fn lfn_checksum_mismatch_is_discarded() {
    let mut img = image();
    // Corrupt the checksum byte of the chain's first entry (root slot 1).
    img[ROOT_START as usize * SECTOR + 32 + 13] ^= 0xFF;

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    // The long name no longer resolves…
    assert_eq!(
        fs.read_file(&format!("/{LONG_NAME}"), &mut buf),
        Err(Error::NotFound)
    );
    // …while both 8.3 names still do.
    assert_eq!(fs.read_file("/README.TXT", &mut buf), Ok(24));
    assert_eq!(fs.read_file("/SUPERL~1.TXT", &mut buf), Ok(18));
}

#[test]
fn broken_lfn_sequence_is_discarded() {
    let mut img = image();
    // Renumber the chain's second entry from 1 to 3 → sequence gap.
    img[ROOT_START as usize * SECTOR + 2 * 32] = 3;

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file(&format!("/{LONG_NAME}"), &mut buf),
        Err(Error::NotFound)
    );
    assert_eq!(fs.read_file("/SUPERL~1.TXT", &mut buf), Ok(18));
}

#[test]
fn lfn_chain_must_start_with_the_last_flag() {
    let mut img = image();
    // Strip 0x40 from root slot 1: a chain is read highest-seq first.
    img[ROOT_START as usize * SECTOR + 32] &= 0x1F;

    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file(&format!("/{LONG_NAME}"), &mut buf),
        Err(Error::NotFound)
    );
}

#[test]
fn lfn_entry_with_a_nonzero_start_cluster_is_discarded() {
    let mut img = image();
    img[ROOT_START as usize * SECTOR + 32 + 26] = 1; // spec: must be 0
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    assert_eq!(
        fs.read_file(&format!("/{LONG_NAME}"), &mut buf),
        Err(Error::NotFound)
    );
}

// --- Path hostility -------------------------------------------------------

#[test]
fn non_absolute_and_empty_paths_are_refused() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    for path in ["", "README.TXT", "SUB/CHILD.BIN", "."] {
        assert_eq!(fs.read_file(path, &mut buf), Err(Error::Path), "{path:?}");
    }
}

#[test]
fn path_traversal_is_refused() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    for path in [
        "/..",
        "/../..",
        "/../../etc/passwd",
        "/SUB/..",
        "/./README.TXT",
        "/SUB//CHILD.BIN",
        "/SUB/../README.TXT",
    ] {
        assert_eq!(fs.read_file(path, &mut buf), Err(Error::Path), "{path:?}");
    }
}

#[test]
fn non_existent_paths_are_not_found() {
    let img = image();
    let fs = mounted(&img);
    let mut buf = [0u8; 64];
    for path in [
        "/NOPE.TXT",
        "/SUB/NOPE.BIN",
        "/SUB/DEEP/NOPE.BIN",
        "/reemplazo filesystem ok",
    ] {
        assert_eq!(
            fs.read_file(path, &mut buf),
            Err(Error::NotFound),
            "{path:?}"
        );
    }
}
