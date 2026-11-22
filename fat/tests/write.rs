//! FS2 write-path tests: adversarial cases plus a model-based oracle.
//!
//! Every test drives the writer through [`Mem`], an in-memory device
//! with the kernel ATA adapter's contract (whole 512-byte sectors,
//! aligned offsets, hard refusal outside the device): a write that
//! escaped the volume or touched the wrong sector would fail on the
//! adapter instead of quietly succeeding. Raw FAT/directory asserts
//! read the image bytes directly — the tests check *on-disk state*
//! (mirrors, freed clusters, cleared LFN slots), not just what the
//! reader reports.

use fat::{BlockDevice, Error, Fat16, Stamp};

// --- Fixed test geometry (same as tests/hostile.rs) -----------------------

const SECTOR: usize = 512;
const TOTAL: usize = 4224; // 2 MiB + a little → 4127 clusters ≥ 4085
const RESERVED: u32 = 1;
const FAT_SECTORS: u32 = 32;
const ROOT_SECTORS: u32 = 32;
const ROOT_ENTRIES: u32 = 512;
const ROOT_START: u32 = RESERVED + 2 * FAT_SECTORS; // 65
const DATA_START: u32 = ROOT_START + ROOT_SECTORS; // 97
const CLUSTERS: u32 = TOTAL as u32 - DATA_START; // 4127 (spc = 1 → 512 B clusters)

const README: &[u8] = b"reemplazo filesystem ok\n";
const LONG_NAME: &str = "SuperLongFileName.txt";
const LONG_CONTENT: &[u8] = b"long file content!";

/// Fixed timestamp for every write: deterministic, inside FAT's range
/// (the crate has no clock; the kernel passes its RTC reading instead).
const STAMP: Stamp = Stamp {
    year: 2026,
    month: 11,
    day: 21,
    hour: 9,
    minute: 30,
    second: 12,
};

// --- The block adapter under test ----------------------------------------

/// A writable in-memory device with the kernel ATA adapter's contract:
/// 512-byte-aligned, whole-sector reads *and* writes only, hard
/// refusal outside the device.
struct Mem {
    data: std::cell::RefCell<Vec<u8>>,
}

impl Mem {
    fn new(data: Vec<u8>) -> Self {
        Self {
            data: std::cell::RefCell::new(data),
        }
    }
}

impl BlockDevice for Mem {
    fn size_bytes(&self) -> u64 {
        self.data.borrow().len() as u64
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        let data = self.data.borrow();
        if end > data.len() as u64 {
            return Err(Error::OutOfRange);
        }
        let start = offset as usize;
        buf.copy_from_slice(&data[start..start + buf.len()]);
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        let mut data = self.data.borrow_mut();
        if end > data.len() as u64 {
            return Err(Error::OutOfRange);
        }
        let start = offset as usize;
        data[start..start + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

/// A read-only device (no `write_at` override → the trait's default
/// [`Error::ReadOnly`] refusal), mirroring hostile.rs's `Strict`.
struct Ro<'a>(&'a [u8]);

impl BlockDevice for Ro<'_> {
    fn size_bytes(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(Error::OutOfRange)?;
        if end > self.0.len() as u64 {
            return Err(Error::OutOfRange);
        }
        let start = offset as usize;
        buf.copy_from_slice(&self.0[start..start + buf.len()]);
        Ok(())
    }
}

/// Mount `mem` (every test starts from a fresh mount, as the kernel's
/// re-mount proof does).
fn mount(mem: &Mem) -> Fat16<'_, Mem> {
    Fat16::mount(mem).expect("well-formed image mounts")
}

/// Read a whole file, asserting the size came back exactly as expected
/// (a short read fails on the length assert, a long one on
/// `BufferTooSmall` inside `read_file`).
fn read_exact(fs: &Fat16<'_, Mem>, path: &str, expect_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; expect_len];
    let n = fs
        .read_file(path, &mut buf)
        .unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    assert_eq!(n, expect_len, "size of {path}");
    buf
}

/// FAT #0 entry of `cluster`, read from the raw image bytes.
fn fat_of(mem: &Mem, cluster: u32) -> u16 {
    let data = mem.data.borrow();
    let off = RESERVED as usize * SECTOR + cluster as usize * 2;
    u16::from_le_bytes([data[off], data[off + 1]])
}

/// Raw root-directory slot bytes.
fn root_raw(mem: &Mem, slot: u32) -> [u8; 32] {
    let data = mem.data.borrow();
    let off = ROOT_START as usize * SECTOR + slot as usize * 32;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&data[off..off + 32]);
    raw
}

// --- Image construction (mirrors hostile.rs's `image()`) ------------------

fn put16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// FAT entry `cluster` in *both* copies (the writer keeps them equal —
/// the mirror test pins that; a formatter writes both).
fn fat_set(img: &mut [u8], cluster: u32, value: u16) {
    let byte = cluster as usize * 2;
    for copy in 0..2 {
        let base = (RESERVED as usize + copy * FAT_SECTORS as usize) * SECTOR + byte;
        put16(img, base, value);
    }
}

fn root_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = ROOT_START as usize * SECTOR + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

/// Subdirectory living at cluster 4 (same layout as hostile.rs).
fn sub_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = DATA_START as usize * SECTOR + 2 * SECTOR + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

fn cluster_off(n: u32) -> usize {
    DATA_START as usize * SECTOR + (n as usize - 2) * SECTOR
}

fn entry(name8: &[u8; 8], ext3: &[u8; 3], attr: u8, cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..8].copy_from_slice(name8);
    e[8..11].copy_from_slice(ext3);
    e[11] = attr;
    put16(&mut e, 20, 0);
    put16(&mut e, 26, cluster);
    put32(&mut e, 28, size);
    e
}

fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &c| {
        (((sum & 1) << 7) | (sum >> 1)).wrapping_add(c)
    })
}

fn lfn_entry(units: &[u16], seq: u8, last: bool, sum: u8) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = seq | if last { 0x40 } else { 0 };
    e[11] = 0x0F;
    e[13] = sum;
    for k in 0..13 {
        let i = usize::from(seq - 1) * 13 + k;
        let unit = if i < units.len() {
            units[i]
        } else if i == units.len() {
            0
        } else {
            0xFFFF
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

fn units(s: &str) -> Vec<u16> {
    s.chars().map(|c| c as u16).collect()
}

/// The well-formed FAT16 volume from FS1's suite: `/README.TXT` (24 B,
/// cluster 2) · `/SuperLongFileName.txt` (LFN over `SUPERL~1.TXT`,
/// cluster 3) · `/SUB/CHILD.BIN` (cluster 5) · `/EMPTY.TXT` ·
/// `/EXACT.BIN` (512 B, cluster 6).
fn image() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL * SECTOR];
    {
        let b = &mut img[0..SECTOR];
        b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MSDOS5.0");
        put16(b, 11, 512);
        b[13] = 1;
        put16(b, 14, RESERVED as u16);
        b[16] = 2;
        put16(b, 17, ROOT_ENTRIES as u16);
        put16(b, 19, 0);
        b[21] = 0xF8;
        put16(b, 22, FAT_SECTORS as u16);
        put16(b, 24, 63);
        put16(b, 26, 255);
        put32(b, 28, 0);
        put32(b, 32, TOTAL as u32);
        b[36] = 0x80;
        b[38] = 0x29;
        put32(b, 39, 0x2026_1121);
        b[43..54].copy_from_slice(b"REEMPLAZO  ");
        b[54..62].copy_from_slice(b"FAT16   ");
        b[510] = 0x55;
        b[511] = 0xAA;
    }

    fat_set(&mut img, 0, 0xFFF8);
    fat_set(&mut img, 1, 0xFFFF);
    for cluster in 2..=6 {
        fat_set(&mut img, cluster, 0xFFFF);
    }

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

    let (c2, c3) = (cluster_off(2), cluster_off(3));
    img[c2..c2 + README.len()].copy_from_slice(README);
    img[c3..c3 + LONG_CONTENT.len()].copy_from_slice(LONG_CONTENT);
    sub_slot(&mut img, 0, &entry(b"CHILD   ", b"BIN", 0x20, 5, 40));
    sub_slot(&mut img, 1, &[0u8; 32]);
    img[cluster_off(5)..cluster_off(5) + 40].fill(0xAB);
    img[cluster_off(6)..cluster_off(6) + 512].fill(0xCD);
    img
}

// --- Create / read-back ---------------------------------------------------

#[test]
fn create_and_read_back_round_trip() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/NEW.TXT", b"hello fs2", STAMP)
            .expect("create");
        // The neighbour must be untouched already.
        assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
    }
    // Re-mount from scratch — no state survives the first mount.
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/NEW.TXT", 9), b"hello fs2");
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

#[test]
fn lowercase_names_are_uppercased_on_disk() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/mixed.txt", b"case test", STAMP)
            .expect("create");
    }
    // The stored 8.3 name is uppercase (the documented rule), and the
    // case-insensitive lookup finds it either way.
    assert_eq!(&root_raw(&mem, 7)[0..11], b"MIXED   TXT");
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/MIXED.TXT", 9), b"case test");
    assert_eq!(read_exact(&fs, "/mixed.txt", 9), b"case test");
}

// --- Overwrite: in place, grow, truncate ----------------------------------

#[test]
fn overwrite_same_size_keeps_the_chain() {
    let mem = Mem::new(image());
    let fat_before: Vec<u8> = mem.data.borrow()
        [RESERVED as usize * SECTOR..(RESERVED as usize + FAT_SECTORS as usize) * SECTOR]
        .to_vec();
    {
        let fs = mount(&mem);
        fs.write_file("/README.TXT", b"reemplazo filesystem NO\n", STAMP)
            .expect("overwrite");
    }
    let fat_after: Vec<u8> = mem.data.borrow()
        [RESERVED as usize * SECTOR..(RESERVED as usize + FAT_SECTORS as usize) * SECTOR]
        .to_vec();
    assert_eq!(
        fat_before, fat_after,
        "same-size overwrite must not touch the FAT"
    );
    assert_eq!(fat_of(&mem, 2), 0xFFFF, "chain head still EOC");

    let fs = mount(&mem);
    assert_eq!(
        read_exact(&fs, "/README.TXT", 24),
        b"reemplazo filesystem NO\n"
    );
    let raw = root_raw(&mem, 0);
    assert_eq!(u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]), 24);
}

#[test]
fn overwrite_grows_across_a_cluster_boundary() {
    let mem = Mem::new(image());
    let payload = [0x5Au8; 600]; // 512 + 88 → two clusters
    {
        let fs = mount(&mem);
        fs.write_file("/README.TXT", &payload, STAMP).expect("grow");
    }
    // The chain now spans cluster 2 → 7 (first free), both mirrors.
    assert_eq!(fat_of(&mem, 2), 7);
    assert_eq!(fat_of(&mem, 7), 0xFFFF);
    let data = mem.data.borrow();
    let fat1 = (RESERVED as usize + FAT_SECTORS as usize) * SECTOR;
    assert_eq!(
        u16::from_le_bytes([data[fat1 + 4], data[fat1 + 5]]),
        7,
        "second FAT mirror must match"
    );
    drop(data);

    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/README.TXT", 600), payload);
}

#[test]
fn overwrite_shorter_truncates_and_frees_the_tail() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/README.TXT", &[0x11u8; 600], STAMP)
            .expect("grow to 2 clusters");
        assert_eq!(fat_of(&mem, 7), 0xFFFF);

        fs.write_file("/README.TXT", &[0x22u8; 100], STAMP)
            .expect("truncate");
    }
    // Tail freed, head kept as EOC, size shrunk.
    assert_eq!(fat_of(&mem, 7), 0, "freed tail cluster");
    assert_eq!(fat_of(&mem, 2), 0xFFFF, "head kept");

    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/README.TXT", 100), vec![0x22u8; 100]);
    let raw = root_raw(&mem, 0);
    assert_eq!(
        u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
        100
    );
}

#[test]
fn truncate_to_empty_frees_the_whole_chain_and_can_regrow() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/README.TXT", &[0x33u8; 600], STAMP)
            .expect("grow to 2 clusters");
        fs.write_file("/README.TXT", b"", STAMP)
            .expect("truncate to empty");
    }
    assert_eq!(fat_of(&mem, 2), 0, "chain freed");
    assert_eq!(fat_of(&mem, 7), 0, "tail freed");
    let raw = root_raw(&mem, 0);
    assert_eq!(
        u16::from_le_bytes([raw[26], raw[27]]),
        0,
        "empty file has no cluster"
    );
    assert_eq!(u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]), 0);

    // Regrow from empty: the freed cluster 2 is reusable.
    {
        let fs = mount(&mem);
        fs.write_file("/README.TXT", b"back", STAMP)
            .expect("regrow");
    }
    assert_eq!(fat_of(&mem, 2), 0xFFFF);
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/README.TXT", 4), b"back");
}

// --- Refusals -------------------------------------------------------------

#[test]
fn full_data_region_refuses_create() {
    let mut img = image();
    for cluster in 2..=CLUSTERS + 1 {
        fat_set(&mut img, cluster, 0xFFFF); // no free cluster anywhere
    }
    let mem = Mem::new(img);
    let fs = mount(&mem);
    assert_eq!(fs.write_file("/NEW.TXT", b"x", STAMP), Err(Error::NoSpace));
    // Nothing was mutated: README still reads.
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

#[test]
fn file_larger_than_the_volume_is_refused() {
    let mem = Mem::new(image());
    let too_big = vec![0u8; (CLUSTERS as usize + 1) * SECTOR];
    let fs = mount(&mem);
    assert_eq!(
        fs.write_file("/HUGE.BIN", &too_big, STAMP),
        Err(Error::NoSpace)
    );
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

#[test]
fn directory_slot_exhaustion_refuses_create() {
    let mut img = image();
    for slot in 7..ROOT_ENTRIES {
        root_slot(&mut img, slot, &entry(b"FILLER  ", b"BIN", 0x20, 0, 0));
    }
    let mem = Mem::new(img);
    let fs = mount(&mem);
    assert_eq!(fs.write_file("/NEW.TXT", b"x", STAMP), Err(Error::NoSpace));
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

#[test]
fn invalid_names_are_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    // Names no FAT name can represent: FAT-illegal characters (also on
    // the long-name path) and paths that are not absolute or escape.
    // (FS2 also refused every long name here; FS3 writes those — see
    // `tests/tree.rs` — so only genuinely unrepresentable names remain.)
    for path in [
        "/a:b.txt",       // ':' is illegal in a long name
        "/x?y.txt",       // '?'
        "/a*b.txt",       // '*'
        "/a\"b.txt",      // '"'
        "/a<b.txt",       // '<'
        "/a|b.txt",       // '|'
        "/a\\b.txt",      // '\'
        "/bad\u{7f}.txt", // DEL is a control character
        "/../escape.txt", // traversal
        "/./here.txt",    // dot component
        "/SUB//X.TXT",    // empty component
        "relative.txt",   // not absolute
        "/",              // no name at all
    ] {
        assert!(
            matches!(
                fs.write_file(path, b"x", STAMP),
                Err(Error::InvalidName) | Err(Error::Path)
            ),
            "{path}"
        );
    }
    // The root is untouched: no entry was created.
    assert_eq!(root_raw(&mem, 7)[0], 0x00);
    // The former `InvalidName` names are now long names (FS3).
    fs.write_file("/waytoolongname.txt", b"long", STAMP)
        .expect("long name is written with an LFN chain");
    assert_eq!(read_exact(&fs, "/waytoolongname.txt", 4), b"long");
}

#[test]
fn create_file_refuses_to_clobber() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    assert_eq!(
        fs.create_file("/README.TXT", b"nope", STAMP),
        Err(Error::Exists)
    );
    // write_file is the create-or-overwrite primitive.
    fs.write_file("/README.TXT", b"replaced", STAMP)
        .expect("overwrite");
    assert_eq!(read_exact(&fs, "/README.TXT", 8), b"replaced");
}

#[test]
fn write_to_a_read_only_device_is_refused() {
    let img = image();
    let dev = Ro(&img);
    let fs = Fat16::mount(&dev).expect("mounts");
    assert_eq!(fs.write_file("/NEW.TXT", b"x", STAMP), Err(Error::ReadOnly));
    // An overwrite attempt fails the same way (the first FAT write is
    // refused before anything can change).
    assert_eq!(
        fs.write_file("/README.TXT", b"y", STAMP),
        Err(Error::ReadOnly)
    );
}

#[test]
fn writing_over_a_directory_is_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    assert_eq!(fs.write_file("/SUB", b"x", STAMP), Err(Error::NotAFile));
    assert_eq!(fs.write_file("/SUB/", b"x", STAMP), Err(Error::NotAFile));
}

#[test]
fn invalid_stamp_is_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    for stamp in [
        Stamp { month: 13, ..STAMP },
        Stamp {
            year: 1979,
            ..STAMP
        },
        Stamp {
            day: 31,
            month: 2,
            ..STAMP
        },
        Stamp { hour: 24, ..STAMP },
    ] {
        assert_eq!(
            fs.write_file("/NEW.TXT", b"x", stamp),
            Err(Error::Stamp),
            "{stamp:?}"
        );
    }
    assert_eq!(root_raw(&mem, 7)[0], 0x00);
}

// --- Corrupt chains (FS1 validators, before any mutation) -----------------

#[test]
fn cyclic_chain_refuses_the_write_before_any_mutation() {
    let mut img = image();
    fat_set(&mut img, 2, 3);
    fat_set(&mut img, 3, 2); // README's chain loops
    let mem = Mem::new(img);
    let before = mem.data.borrow().clone();

    let fs = mount(&mem);
    assert_eq!(
        fs.write_file("/README.TXT", b"new", STAMP),
        Err(Error::BadChain)
    );
    assert_eq!(
        *mem.data.borrow(),
        before,
        "refused write must not touch the disk"
    );
}

#[test]
fn out_of_range_chain_refuses_the_write_before_any_mutation() {
    let mut img = image();
    fat_set(&mut img, 2, (CLUSTERS + 2) as u16); // one past the data region
    let mem = Mem::new(img);
    let before = mem.data.borrow().clone();

    let fs = mount(&mem);
    assert_eq!(
        fs.write_file("/README.TXT", b"new", STAMP),
        Err(Error::BadChain)
    );
    assert_eq!(
        *mem.data.borrow(),
        before,
        "refused write must not touch the disk"
    );
}

// --- Freeing discipline ---------------------------------------------------

#[test]
fn truncate_never_frees_another_files_cluster() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        // Grow EXACT.BIN (cluster 6) to two clusters, then truncate it
        // back — the free must hit cluster 7 only.
        fs.write_file("/EXACT.BIN", &[0xABu8; 700], STAMP)
            .expect("grow");
        assert_eq!(fat_of(&mem, 6), 7);
        fs.write_file("/EXACT.BIN", &[0xCDu8; 100], STAMP)
            .expect("truncate");
    }
    assert_eq!(fat_of(&mem, 7), 0, "own tail freed");
    assert_eq!(fat_of(&mem, 6), 0xFFFF, "own head kept");
    // Neighbours' clusters untouched.
    for cluster in [2u32, 3, 4, 5] {
        assert_eq!(fat_of(&mem, cluster), 0xFFFF, "cluster {cluster}");
    }
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
    assert_eq!(read_exact(&fs, "/SUB/CHILD.BIN", 40), vec![0xABu8; 40]);
}

#[test]
fn rewrite_reuses_a_freed_cluster_without_double_free() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/EXACT.BIN", &[0x11u8; 700], STAMP)
            .expect("grow to 6→7");
        fs.write_file("/EXACT.BIN", &[0x22u8; 100], STAMP)
            .expect("truncate → 7 free");
        assert_eq!(fat_of(&mem, 7), 0);

        // A new file must be able to take cluster 7 again (first-fit
        // after 2..=6), and the rewrite must not double-free anything.
        fs.write_file("/AGAIN.BIN", &[0x33u8; 512], STAMP)
            .expect("re-allocate");
    }
    assert_eq!(fat_of(&mem, 7), 0xFFFF, "re-allocated exactly once");
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/AGAIN.BIN", 512), vec![0x33u8; 512]);
    assert_eq!(read_exact(&fs, "/EXACT.BIN", 100), vec![0x22u8; 100]);
    assert_eq!(fat_of(&mem, 2), 0xFFFF, "README's cluster still in use");
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

// --- Directories ----------------------------------------------------------

#[test]
fn create_inside_an_existing_subdirectory() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/SUB/NEW.BIN", b"sub content", STAMP)
            .expect("create in subdirectory");
        // Neighbours again.
        assert_eq!(read_exact(&fs, "/SUB/CHILD.BIN", 40), vec![0xABu8; 40]);
        assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
    }
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/SUB/NEW.BIN", 11), b"sub content");
    // The slot lives in SUB's own cluster, right after CHILD.BIN.
    let raw = {
        let data = mem.data.borrow();
        let mut raw = [0u8; 32];
        let off = cluster_off(4) + 32;
        raw.copy_from_slice(&data[off..off + 32]);
        raw
    };
    assert_eq!(&raw[0..11], b"NEW     BIN");
    assert_eq!(
        u16::from_le_bytes([raw[26], raw[27]]),
        7,
        "allocated cluster"
    );
    assert_eq!(
        u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]]),
        11,
        "size"
    );
}

#[test]
fn stale_lfn_entries_are_cleared_when_reusing_a_slot() {
    let mut img = image();
    // Slots 7-8: an orphaned LFN chain; slot 9: its deleted 8.3 entry.
    let gone = units("GoneLongName.txt");
    let sum = checksum(b"GONEL~1 TXT");
    root_slot(&mut img, 7, &lfn_entry(&gone, 2, true, sum));
    root_slot(&mut img, 8, &lfn_entry(&gone, 1, false, sum));
    root_slot(&mut img, 9, &entry(b"GONEL~1 ", b"TXT", 0x20, 0, 0));
    img[ROOT_START as usize * SECTOR + 9 * 32] = 0xE5; // delete only the 8.3 entry

    let mem = Mem::new(img);
    let fs = mount(&mem);
    let mut buf = [0u8; 32];
    assert_eq!(
        fs.read_file("/GoneLongName.txt", &mut buf),
        Err(Error::NotFound),
        "the orphaned chain already resolves to nothing"
    );

    fs.write_file("/NEW.TXT", b"x", STAMP).expect("create");
    // The stale LFN slots must be cleared, and the new entry landed in
    // the freed slot 9 (the first free slot in directory order).
    assert_eq!(root_raw(&mem, 7)[0], 0xE5, "stale LFN part cleared");
    assert_eq!(root_raw(&mem, 8)[0], 0xE5, "stale LFN part cleared");
    assert_eq!(&root_raw(&mem, 9)[0..11], b"NEW     TXT");
    assert_eq!(read_exact(&fs, "/NEW.TXT", 1), b"x");
}

// --- Long names -----------------------------------------------------------

#[test]
fn overwrite_through_the_long_name_keeps_the_lfn_chain() {
    let mem = Mem::new(image());
    let lfn_slots: Vec<u8> = mem.data.borrow()
        [ROOT_START as usize * SECTOR + 32..ROOT_START as usize * SECTOR + 4 * 32]
        .to_vec();
    {
        let fs = mount(&mem);
        // Same length as LONG_CONTENT (18 B) → in-place overwrite via the LFN.
        fs.write_file(&format!("/{LONG_NAME}"), b"NEW long content!!", STAMP)
            .expect("overwrite through LFN");
    }
    let lfn_after: Vec<u8> = mem.data.borrow()
        [ROOT_START as usize * SECTOR + 32..ROOT_START as usize * SECTOR + 4 * 32]
        .to_vec();
    // Slots 1-2 are the LFN parts — untouched; slot 3's name too.
    assert_eq!(lfn_slots[..64], lfn_after[..64], "LFN parts unchanged");
    assert_eq!(&lfn_after[64..75], b"SUPERL~1TXT", "8.3 name unchanged");

    let fs = mount(&mem);
    assert_eq!(
        read_exact(&fs, &format!("/{LONG_NAME}"), 18),
        b"NEW long content!!"
    );
    assert_eq!(read_exact(&fs, "/SUPERL~1.TXT", 18), b"NEW long content!!");
}

// --- Invariants -----------------------------------------------------------

#[test]
fn both_fat_mirrors_stay_in_sync() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/A.TXT", &[1u8; 900], STAMP).expect("grow");
        fs.write_file("/A.TXT", &[2u8; 100], STAMP).expect("shrink");
        fs.write_file("/B.TXT", &[3u8; 1], STAMP).expect("create");
        fs.write_file("/README.TXT", b"changed", STAMP)
            .expect("overwrite");
        fs.write_file("/SUB/C.BIN", &[4u8; 7000], STAMP)
            .expect("big file in subdir (14 clusters)");
    }
    let data = mem.data.borrow();
    let fat0 =
        &data[RESERVED as usize * SECTOR..(RESERVED as usize + FAT_SECTORS as usize) * SECTOR];
    let fat1 = &data[(RESERVED as usize + FAT_SECTORS as usize) * SECTOR
        ..(RESERVED as usize + 2 * FAT_SECTORS as usize) * SECTOR];
    assert_eq!(fat0, fat1, "both FAT copies must be byte-identical");
    drop(data);

    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/A.TXT", 100), vec![2u8; 100]);
    assert_eq!(read_exact(&fs, "/B.TXT", 1), vec![3u8; 1]);
    assert_eq!(read_exact(&fs, "/SUB/C.BIN", 7000), vec![4u8; 7000]);
    assert_eq!(read_exact(&fs, "/README.TXT", 7), b"changed");
}

// --- The oracle -----------------------------------------------------------

/// xorshift64 — deterministic, no `rand` crate (same trick as
/// `editorbuf`'s tests). State is never zero (fixed nonzero seed), so
/// the shift feedback is well-defined.
fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// A pseudo-random sequence of create/overwrite/truncate operations
/// against a model `Vec` map: after **every** operation the volume is
/// re-mounted from scratch and every file in the model is read back
/// byte-exact (length and content), plus `/README.TXT` — which the
/// oracle never writes — must stay intact.
#[test]
fn oracle_randomized_write_sequence_matches_a_model() {
    const POOL: [&str; 8] = [
        "ALPHA.TXT",
        "BETA.BIN",
        "GAMMA.LOG",
        "DELTA.DAT",
        "EPSILON.TXT",
        "ZETA.BIN",
        "ETA.TXT",
        "THETA.DAT",
    ];
    let mem = Mem::new(image());
    let mut model: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut state = 0x2026_1121u64; // fixed seed
    let mut op_byte = 0u8;

    for i in 0..120usize {
        let name = POOL[(xorshift64(&mut state) as usize) % POOL.len()];
        let len = if i % 7 == 0 {
            0 // periodic truncate-to-empty
        } else {
            (xorshift64(&mut state) % 1501) as usize // crosses 512-byte clusters
        };
        op_byte = op_byte.wrapping_add(0x9E).wrapping_add(len as u8);
        let data: Vec<u8> = (0..len).map(|j| (j as u8) ^ op_byte).collect();

        {
            let fs = mount(&mem);
            fs.write_file(&format!("/{name}"), &data, STAMP)
                .unwrap_or_else(|e| panic!("op {i} write {name} len {len}: {e:?}"));
            // The no-clobber variant keeps refusing once the file exists.
            if i % 13 == 0 && model.iter().any(|(n, _)| *n == name) {
                assert_eq!(
                    fs.create_file(&format!("/{name}"), &data, STAMP),
                    Err(Error::Exists),
                    "op {i} {name}"
                );
            }
        }

        match model.iter_mut().find(|(n, _)| *n == name) {
            Some(entry) => entry.1 = data,
            None => model.push((name, data)),
        }

        // Re-mount from scratch and verify everything.
        let fs = mount(&mem);
        for (n, expect) in &model {
            let mut buf = vec![0u8; expect.len()];
            let got = fs
                .read_file(&format!("/{n}"), &mut buf)
                .unwrap_or_else(|e| panic!("op {i} read {n}: {e:?}"));
            assert_eq!(got, expect.len(), "op {i} size of {n}");
            assert_eq!(&buf[..got], &expect[..], "op {i} content of {n}");
        }
        let mut readme = [0u8; 24];
        let n = fs.read_file("/README.TXT", &mut readme).expect("README");
        assert_eq!(&readme[..n], README, "op {i}: README must stay intact");
    }

    // Both mirrors stayed in sync through the whole sequence.
    let data = mem.data.borrow();
    let fat0 =
        &data[RESERVED as usize * SECTOR..(RESERVED as usize + FAT_SECTORS as usize) * SECTOR];
    let fat1 = &data[(RESERVED as usize + FAT_SECTORS as usize) * SECTOR
        ..(RESERVED as usize + 2 * FAT_SECTORS as usize) * SECTOR];
    assert_eq!(fat0, fat1, "FAT mirrors diverged");
}
