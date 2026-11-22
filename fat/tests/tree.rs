//! FS3 tests: directory creation, nested paths and LFN writes.
//!
//! Same discipline as FS2's suite (`tests/write.rs`): every test drives
//! the writer through [`Mem`] — an in-memory device with the kernel ATA
//! adapter's contract (whole 512-byte sectors, aligned offsets, hard
//! refusal outside the device) — and the raw image bytes are checked
//! directly, so the assertions are about *on-disk state*, not only what
//! the reader happens to report. The LFN oracle below (`spec_checksum`,
//! `spec_lfn_entry`) is a second, independent implementation of the FAT
//! spec's entry layout: the writer's bytes are compared against it.

use fat::{BlockDevice, Error, Fat16, Kind, Stamp};

// --- Fixed test geometry --------------------------------------------------
//
// 4 KiB clusters (the installer image's geometry), big enough for a
// 128-entry subdirectory — the randomized tree test fills directories,
// and 512-byte clusters would exhaust 16 slots long before the workload
// ends. 20 MiB still leaves ~4980 clusters, safely inside FAT16.

const SECTOR: usize = 512;
const SPC: u32 = 8; // 4 KiB clusters
const TOTAL: usize = 40000; // 20 MiB → ~4980 clusters ≥ 4085
const RESERVED: u32 = 1;
const FAT_SECTORS: u32 = 32;
const ROOT_SECTORS: u32 = 32;
const ROOT_ENTRIES: u32 = 512;
const ROOT_START: u32 = RESERVED + 2 * FAT_SECTORS; // 65
const DATA_START: u32 = ROOT_START + ROOT_SECTORS; // 97
const CLUSTERS: u32 = (TOTAL as u32 - DATA_START) / SPC;

const README: &[u8] = b"reemplazo filesystem ok\n";

/// Fixed timestamp for every write (the crate has no clock).
const STAMP: Stamp = Stamp {
    year: 2026,
    month: 11,
    day: 22,
    hour: 10,
    minute: 15,
    second: 42,
};

// --- The block adapter under test ----------------------------------------

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

fn mount(mem: &Mem) -> Fat16<'_, Mem> {
    Fat16::mount(mem).expect("well-formed image mounts")
}

fn read_exact(fs: &Fat16<'_, Mem>, path: &str, expect_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; expect_len];
    let n = fs
        .read_file(path, &mut buf)
        .unwrap_or_else(|e| panic!("read {path}: {e:?}"));
    assert_eq!(n, expect_len, "size of {path}");
    buf
}

/// FAT #0 entry of `cluster`, straight from the image bytes.
fn fat_of(mem: &Mem, cluster: u32) -> u16 {
    let data = mem.data.borrow();
    let off = RESERVED as usize * SECTOR + cluster as usize * 2;
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn put16(img: &mut [u8], off: usize, v: u16) {
    img[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn put32(img: &mut [u8], off: usize, v: u32) {
    img[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn fat_set(img: &mut [u8], cluster: u32, value: u16) {
    let byte = cluster as usize * 2;
    for copy in 0..2 {
        let base = (RESERVED as usize + copy * FAT_SECTORS as usize) * SECTOR + byte;
        put16(img, base, value);
    }
}

fn cluster_off(n: u32) -> usize {
    DATA_START as usize * SECTOR + (n as usize - 2) * (SPC as usize * SECTOR)
}

fn raw_entry(name8: &[u8; 8], ext3: &[u8; 3], attr: u8, cluster: u16, size: u32) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0..8].copy_from_slice(name8);
    e[8..11].copy_from_slice(ext3);
    e[11] = attr;
    put16(&mut e, 26, cluster);
    put32(&mut e, 28, size);
    e
}

fn root_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = ROOT_START as usize * SECTOR + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

fn sub_slot(img: &mut [u8], slot: u32, entry: &[u8; 32]) {
    let off = cluster_off(4) + slot as usize * 32;
    img[off..off + 32].copy_from_slice(entry);
}

/// Slot bytes of a directory cluster.
fn cluster_raw(mem: &Mem, cluster: u32, slot: u32) -> [u8; 32] {
    let data = mem.data.borrow();
    let off = cluster_off(cluster) + slot as usize * 32;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&data[off..off + 32]);
    raw
}

fn root_raw(mem: &Mem, slot: u32) -> [u8; 32] {
    let data = mem.data.borrow();
    let off = ROOT_START as usize * SECTOR + slot as usize * 32;
    let mut raw = [0u8; 32];
    raw.copy_from_slice(&data[off..off + 32]);
    raw
}

fn name_of(raw: &[u8; 32]) -> &[u8; 11] {
    raw[..11].try_into().expect("11-byte name field")
}

fn cluster_of(raw: &[u8; 32]) -> u32 {
    u32::from(u16::from_le_bytes([raw[26], raw[27]]))
}

fn size_of(raw: &[u8; 32]) -> u32 {
    u32::from_le_bytes([raw[28], raw[29], raw[30], raw[31]])
}

// --- The independent LFN oracle (FAT spec §7.4) --------------------------

fn spec_checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, &c| {
        (((sum & 1) << 7) | (sum >> 1)).wrapping_add(c)
    })
}

/// One spec-shaped LFN entry: `seq` of `total`, 13 units, zero
/// terminator, `0xFFFF` padding.
fn spec_lfn_entry(units: &[u16], seq: u8, total: u8, sum: u8) -> [u8; 32] {
    let mut e = [0u8; 32];
    e[0] = seq | if seq == total { 0x40 } else { 0 };
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

/// UTF-16 units of a name, surrogate pairs included.
fn utf16(s: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for c in s.chars() {
        let cp = c as u32;
        if cp > 0xFFFF {
            let rest = cp - 0x1_0000;
            out.push((0xD800 + (rest >> 10)) as u16);
            out.push((0xDC00 + (rest & 0x3FF)) as u16);
        } else {
            out.push(cp as u16);
        }
    }
    out
}

/// Numeric suffix of an 8.3 alias (`LONGFI~12TXT` → 12), 0 when the
/// name has no `~N` tail.
fn alias_suffix(name: &[u8; 11]) -> u32 {
    let Some(pos) = name.iter().position(|&b| b == b'~') else {
        return 0;
    };
    let mut v = 0u32;
    for &b in &name[pos + 1..8] {
        if b.is_ascii_digit() {
            v = v * 10 + u32::from(b - b'0');
        } else {
            break;
        }
    }
    v
}

/// The whole LFN chain the writer must emit for `name` under alias
/// `short`, in physical directory order (highest sequence first).
fn spec_chain(name: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let units = utf16(name);
    let total = units.len().div_ceil(13) as u8;
    let sum = spec_checksum(short);
    (1..=total)
        .rev()
        .map(|seq| spec_lfn_entry(&units, seq, total, sum))
        .collect()
}

// --- Base image -----------------------------------------------------------

/// A well-formed FAT16 volume: `/README.TXT` (24 B, cluster 2),
/// `/SUB/` (cluster 4) and `/SUB/CHILD.BIN` (cluster 5). Free clusters:
/// 3 and 6..=CLUSTERS+1. Root slots 2.. are free.
fn image() -> Vec<u8> {
    let mut img = vec![0u8; TOTAL * SECTOR];
    {
        let b = &mut img[0..SECTOR];
        b[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        b[3..11].copy_from_slice(b"MSDOS5.0");
        put16(b, 11, 512);
        b[13] = SPC as u8;
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
        put32(b, 39, 0x2026_1122);
        b[43..54].copy_from_slice(b"REEMPLAZO  ");
        b[54..62].copy_from_slice(b"FAT16   ");
        b[510] = 0x55;
        b[511] = 0xAA;
    }
    fat_set(&mut img, 0, 0xFFF8);
    fat_set(&mut img, 1, 0xFFFF);
    for cluster in [2u32, 4, 5] {
        fat_set(&mut img, cluster, 0xFFFF);
    }
    root_slot(
        &mut img,
        0,
        &raw_entry(b"README  ", b"TXT", 0x20, 2, README.len() as u32),
    );
    root_slot(&mut img, 1, &raw_entry(b"SUB     ", b"   ", 0x10, 4, 0));
    sub_slot(&mut img, 0, &raw_entry(b"CHILD   ", b"BIN", 0x20, 5, 40));
    let c2 = cluster_off(2);
    img[c2..c2 + README.len()].copy_from_slice(README);
    img[cluster_off(5)..cluster_off(5) + 40].fill(0xAB);
    img
}

/// Count the LFN entries immediately before `slot` in the root.
fn lfn_count_before_root(mem: &Mem, slot: u32) -> u32 {
    let mut n = 0;
    let mut back = 1;
    while back <= slot {
        let raw = root_raw(mem, slot - back);
        if raw[11] == 0x0F && raw[0] != 0xE5 {
            n += 1;
        } else {
            break;
        }
        back += 1;
    }
    n
}

// --- mkdir ---------------------------------------------------------------

#[test]
fn mkdir_round_trips_through_a_remount() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.create_dir("/NEWDIR", STAMP).expect("mkdir");
        assert_eq!(fs.kind("/NEWDIR"), Ok(Kind::Dir));
        assert_eq!(fs.kind("/NEWDIR/"), Ok(Kind::Dir));
        assert_eq!(fs.kind("/README.TXT"), Ok(Kind::File));
        assert_eq!(fs.kind("/NOPE"), Err(Error::NotFound));
    }
    // Fresh mount: only the device holds the new directory.
    let fs = mount(&mem);
    assert_eq!(fs.kind("/newdir"), Ok(Kind::Dir));
    // The parent entry is a directory with a real cluster and size 0.
    let raw = root_raw(&mem, 2);
    assert_eq!(name_of(&raw), b"NEWDIR     ");
    assert_eq!(raw[11] & 0x10, 0x10);
    assert_eq!(size_of(&raw), 0);
    let cluster = cluster_of(&raw);
    assert!((2..=CLUSTERS + 1).contains(&cluster));
    assert_eq!(fat_of(&mem, cluster), 0xFFFF, "directory chain is EOC");
}

#[test]
fn mkdir_writes_dot_and_dotdot_with_the_right_clusters() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.create_dir("/A", STAMP).expect("mkdir A");
    fs.create_dir("/A/B", STAMP).expect("mkdir A/B");
    let a = cluster_of(&root_raw(&mem, 2));
    let b_entry = cluster_raw(&mem, a, 2); // after ".", ".."
    assert_eq!(name_of(&b_entry), b"B          ");
    let b = cluster_of(&b_entry);
    assert_ne!(a, b);

    let dot = cluster_raw(&mem, b, 0);
    let dotdot = cluster_raw(&mem, b, 1);
    assert_eq!(name_of(&dot), b".          ");
    assert_eq!(name_of(&dotdot), b"..         ");
    assert_eq!(cluster_of(&dot), b, ". is its own cluster");
    assert_eq!(cluster_of(&dotdot), a, ".. is the parent's cluster");
    assert_eq!(dot[11] & 0x10, 0x10);
    assert_eq!(dotdot[11] & 0x10, 0x10);
    assert_eq!(size_of(&dot), 0);
    assert_eq!(size_of(&dotdot), 0);

    // A's own ".." points at the root, which has no cluster: 0.
    assert_eq!(cluster_of(&cluster_raw(&mem, a, 1)), 0);
}

#[test]
fn root_never_gets_dot_or_dotdot_entries() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.create_dir("/A", STAMP).expect("mkdir");
    for slot in 0..ROOT_ENTRIES {
        let raw = root_raw(&mem, slot);
        assert_ne!(name_of(&raw), b".          ", "slot {slot}");
        assert_ne!(name_of(&raw), b"..         ", "slot {slot}");
    }
}

#[test]
fn mkdir_in_a_subdirectory_lands_in_that_cluster() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.create_dir("/SUB/NEWDIR", STAMP).expect("mkdir in SUB");
    let entry = cluster_raw(&mem, 4, 1); // slot 1: after CHILD.BIN
    assert_eq!(name_of(&entry), b"NEWDIR     ");
    let new = cluster_of(&entry);
    // Its ".." is SUB's own cluster, not the root.
    assert_eq!(cluster_of(&cluster_raw(&mem, new, 1)), 4);
    let fs2 = mount(&mem);
    assert_eq!(fs2.kind("/SUB/NEWDIR"), Ok(Kind::Dir));
}

#[test]
fn create_dir_refuses_collisions() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.create_dir("/TAKEN", STAMP).expect("mkdir");
    assert_eq!(fs.create_dir("/TAKEN", STAMP), Err(Error::Exists));
    assert_eq!(fs.create_dir("/README.TXT", STAMP), Err(Error::Exists));
    // Nothing was mutated by the refusals.
    assert_eq!(root_raw(&mem, 3)[0], 0x00);
}

#[test]
fn create_dir_requires_an_existing_parent() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    assert_eq!(fs.create_dir("/NOPE/CHILD", STAMP), Err(Error::NotFound));
    assert_eq!(
        fs.create_dir("/README.TXT/CHILD", STAMP),
        Err(Error::NotAFile)
    );
}

#[test]
fn create_dir_all_builds_missing_parents_and_is_idempotent() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.create_dir_all("/A/B/C/D", STAMP).expect("mkdir -p");
        fs.create_dir_all("/A/B/C/D", STAMP).expect("idempotent");
        fs.create_dir_all("/A/B/C/D/", STAMP)
            .expect("trailing slash");
        assert_eq!(fs.kind("/A"), Ok(Kind::Dir));
        assert_eq!(fs.kind("/A/B"), Ok(Kind::Dir));
        assert_eq!(fs.kind("/A/B/C"), Ok(Kind::Dir));
        assert_eq!(fs.kind("/A/B/C/D"), Ok(Kind::Dir));
    }
    let fs = mount(&mem);
    assert_eq!(fs.kind("/a/b/c/d"), Ok(Kind::Dir));
}

#[test]
fn create_dir_all_refuses_a_file_in_the_middle() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    assert_eq!(
        fs.create_dir_all("/README.TXT/SUB", STAMP),
        Err(Error::NotAFile)
    );
    assert_eq!(fs.create_dir_all("/", STAMP), Err(Error::Path));
    assert_eq!(fs.create_dir_all("relative", STAMP), Err(Error::Path));
}

// --- Nested write / read -------------------------------------------------

#[test]
fn write_file_all_creates_parents_and_round_trips() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file_all("/A/B/C/FILE.BIN", b"nested payload", STAMP)
            .expect("write_file_all");
        assert_eq!(read_exact(&fs, "/A/B/C/FILE.BIN", 14), b"nested payload");
        // A long nested name in the same tree.
        fs.write_file_all("/A/B/C/deeply-named-file.txt", b"long", STAMP)
            .expect("long nested name");
    }
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/a/b/c/file.bin", 14), b"nested payload");
    assert_eq!(read_exact(&fs, "/A/B/C/deeply-named-file.txt", 4), b"long");
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

#[test]
fn five_level_parent_chain_reads_back() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file_all("/L1/L2/L3/L4/L5/leaf.txt", b"leaf", STAMP)
            .expect("deep write");
    }
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/L1/L2/L3/L4/L5/leaf.txt", 4), b"leaf");
    for path in ["/L1", "/L1/L2", "/L1/L2/L3", "/L1/L2/L3/L4"] {
        assert_eq!(fs.kind(path), Ok(Kind::Dir), "{path}");
    }
    // Every ".." on the chain points at its own parent.
    let l1 = cluster_of(&root_raw(&mem, 2));
    let l2 = cluster_of(&cluster_raw(&mem, l1, 2));
    assert_eq!(cluster_of(&cluster_raw(&mem, l2, 1)), l1);
    assert_eq!(cluster_of(&cluster_raw(&mem, l1, 1)), 0);
}

#[test]
fn write_file_all_overwrites_in_place() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.write_file_all("/D/x.txt", b"first", STAMP)
        .expect("write");
    fs.write_file_all("/D/x.txt", b"second!", STAMP)
        .expect("overwrite");
    assert_eq!(read_exact(&fs, "/D/x.txt", 7), b"second!");
    // The parent was found, not recreated: still one "D" entry.
    assert_eq!(fs.kind("/D"), Ok(Kind::Dir));
    assert_eq!(read_exact(&fs, "/README.TXT", README.len()), README);
}

// --- LFN bytes -----------------------------------------------------------

#[test]
fn long_name_entries_match_the_spec_vector_byte_for_byte() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    // "SuperLongFileName.txt" is the FS1/FS2 fixture's long name: the
    // real-world Windows alias is SUPERL~1.TXT (6 chars + ~1), and the
    // expected chain is derived from the spec by the oracle above.
    fs.write_file("/SuperLongFileName.txt", b"x", STAMP)
        .expect("create long name");

    let short = *b"SUPERL~1TXT";
    let chain = spec_chain("SuperLongFileName.txt", &short);
    assert_eq!(chain.len(), 2, "19 units → two LFN entries");
    // Root slots 2.. are free: LFN entries first (highest sequence),
    // then the 8.3 entry last.
    assert_eq!(root_raw(&mem, 2), chain[0], "seq 2, 0x40 set");
    assert_eq!(root_raw(&mem, 3), chain[1], "seq 1");
    assert_eq!(root_raw(&mem, 2)[0], 0x42, "0x40 | 2");
    assert_eq!(root_raw(&mem, 3)[0], 0x01);
    assert_eq!(root_raw(&mem, 2)[13], spec_checksum(&short));
    let entry = root_raw(&mem, 4);
    assert_eq!(name_of(&entry), &short);
    assert_eq!(entry[11] & 0x20, 0x20);
    assert_eq!(size_of(&entry), 1);

    // The FS1 reader (a different implementation of the checksum and
    // sequence rules) assembles the same name back.
    assert_eq!(read_exact(&fs, "/SuperLongFileName.txt", 1), b"x");
    assert_eq!(read_exact(&fs, "/SUPERL~1.TXT", 1), b"x");
}

#[test]
fn thirteen_and_fourteen_char_names_use_one_and_two_entries() {
    for (name, entries) in [
        ("abcdefghijklm", 1u32),            // 13 units → exactly one entry
        ("abcdefghijklmn", 2),              // 14 → two
        ("abcdefghijklmnopqrstuvwxyz", 2),  // 26
        ("abcdefghijklmnopqrstuvwxyz0", 3), // 27
    ] {
        let mem = Mem::new(image());
        let fs = mount(&mem);
        fs.write_file(&format!("/{name}"), b"x", STAMP)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
        // The 8.3 entry is the first non-LFN slot after the chain.
        let mut slot = 2u32;
        while root_raw(&mem, slot)[11] == 0x0F {
            slot += 1;
        }
        assert_eq!(slot - 2, entries, "{name}: LFN entry count");
        assert_eq!(lfn_count_before_root(&mem, slot), entries, "{name}");
        assert_eq!(read_exact(&fs, &format!("/{name}"), 1), b"x");
    }
}

#[test]
fn max_length_name_uses_twenty_entries_and_round_trips() {
    let name = "a".repeat(255);
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.write_file(&format!("/{name}"), b"max", STAMP)
        .expect("255");
    // 255 units / 13 = 20 entries, then the 8.3 entry.
    let mut slot = 2u32;
    while root_raw(&mem, slot)[11] == 0x0F {
        slot += 1;
    }
    assert_eq!(slot - 2, 20, "twenty LFN entries");
    assert_eq!(root_raw(&mem, 2)[0] & 0x40, 0x40, "last flag on the first");
    assert_eq!(root_raw(&mem, 21)[0], 0x01);
    assert_eq!(read_exact(&fs, &format!("/{name}"), 3), b"max");
}

#[test]
fn name_longer_than_255_units_is_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    let name = "a".repeat(256);
    assert_eq!(
        fs.write_file(&format!("/{name}"), b"x", STAMP),
        Err(Error::InvalidName)
    );
    assert_eq!(root_raw(&mem, 2)[0], 0x00, "nothing written");
}

#[test]
fn four_byte_utf8_name_exceeding_the_cap_is_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    // 128 emoji × 2 units = 256 units → refused (surrogates count two).
    let name = "😀".repeat(128);
    assert_eq!(
        fs.write_file(&format!("/{name}.txt"), b"x", STAMP),
        Err(Error::InvalidName)
    );
}

// --- Aliases -------------------------------------------------------------

#[test]
fn alias_suffix_increments_on_collisions() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    for (i, name) in [
        "LongFileNameOne.txt",
        "LongFileNameTwo.txt",
        "LongFileNameThree.txt",
    ]
    .iter()
    .enumerate()
    {
        fs.write_file(&format!("/{name}"), format!("body {i}").as_bytes(), STAMP)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    let mut aliases = Vec::new();
    for slot in 2..ROOT_ENTRIES {
        let raw = root_raw(&mem, slot);
        if raw[0] == 0x00 {
            break;
        }
        if raw[11] != 0x0F {
            aliases.push(*name_of(&raw));
        }
    }
    assert_eq!(aliases.len(), 3);
    assert_eq!(&aliases[0], b"LONGFI~1TXT");
    assert_eq!(&aliases[1], b"LONGFI~2TXT");
    assert_eq!(&aliases[2], b"LONGFI~3TXT");
    // Every alias resolves too, and the long names are distinct.
    for (i, name) in [
        "LongFileNameOne.txt",
        "LongFileNameTwo.txt",
        "LongFileNameThree.txt",
    ]
    .iter()
    .enumerate()
    {
        assert_eq!(
            read_exact(&fs, &format!("/{name}"), 6),
            format!("body {i}").as_bytes()
        );
    }
    assert_eq!(read_exact(&fs, "/LONGFI~2.TXT", 6), b"body 1");
}

#[test]
fn alias_probe_passes_ten_and_stays_unique() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    for i in 0..12 {
        let name = format!("aaaaaa-long-{i}.txt");
        fs.write_file(&format!("/{name}"), b"x", STAMP)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    let mut aliases: Vec<[u8; 11]> = Vec::new();
    for slot in 2..ROOT_ENTRIES {
        let raw = root_raw(&mem, slot);
        if raw[0] == 0x00 {
            break;
        }
        if raw[11] != 0x0F {
            aliases.push(*name_of(&raw));
        }
    }
    assert_eq!(aliases.len(), 12);
    for (i, a) in aliases.iter().enumerate() {
        for b in &aliases[i + 1..] {
            assert_ne!(a, b, "aliases must be unique");
        }
    }
    // The numeric tail ran 1..=12: the probe shrank the base prefix to
    // make room for the second digit instead of colliding at ~10.
    let suffixes: Vec<u32> = aliases.iter().map(alias_suffix).collect();
    assert_eq!(suffixes, (1..=12).collect::<Vec<u32>>());
    for i in 0..12 {
        assert_eq!(
            read_exact(&fs, &format!("/aaaaaa-long-{i}.txt"), 1),
            b"x",
            "{i}"
        );
    }
}

#[test]
fn alias_avoids_an_existing_short_name() {
    let mut img = image();
    // A real 8.3 file that occupies the alias the name would prefer.
    root_slot(&mut img, 2, &raw_entry(b"LONGFI~1", b"TXT", 0x20, 0, 0));
    let mem = Mem::new(img);
    let fs = mount(&mem);
    fs.write_file("/LongFileName.txt", b"x", STAMP)
        .expect("create");
    let mut alias = None;
    for slot in 3..ROOT_ENTRIES {
        let raw = root_raw(&mem, slot);
        if raw[0] == 0x00 {
            break;
        }
        if raw[11] != 0x0F {
            alias = Some(*name_of(&raw));
        }
    }
    assert_eq!(alias, Some(*b"LONGFI~2TXT"));
    assert_eq!(read_exact(&fs, "/LongFileName.txt", 1), b"x");
    // The original 8.3 file is untouched (it is still empty).
    assert_eq!(fs.read_file("/LONGFI~1.TXT", &mut [0u8; 1]), Ok(0));
}

#[test]
fn non_ascii_alias_is_a_legal_8_3_name() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.write_file("/niño-café.txt", b"unicode", STAMP)
        .expect("create");
    let raw = root_raw(&mem, 2); // one LFN entry (13 units), then 8.3
    assert_eq!(raw[11], 0x0F);
    let entry = root_raw(&mem, 3);
    for &b in name_of(&entry) {
        assert!(
            b.is_ascii_alphanumeric() || b == b' ' || b"$%'-_@~`!(){}^#&".contains(&b),
            "alias byte {b:#04x} is not legal 8.3"
        );
    }
    assert_eq!(read_exact(&fs, "/niño-café.txt", 7), b"unicode");
}

#[test]
fn unicode_and_non_bmp_names_round_trip() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    let names = [
        "niño.txt",
        "café-au-lait.txt",
        "emoji-😀-file.txt",
        "Ω-mega.txt",
    ];
    for (i, name) in names.iter().enumerate() {
        fs.write_file(&format!("/{name}"), format!("u{i}").as_bytes(), STAMP)
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    for (i, name) in names.iter().enumerate() {
        assert_eq!(
            read_exact(&fs, &format!("/{name}"), 2),
            format!("u{i}").as_bytes()
        );
    }
    // The non-BMP name's chain stores the surrogate pair (2 units for
    // the emoji), and the FS1 reader matches the UTF-8 path against it.
    let units = utf16("emoji-😀-file.txt");
    assert_eq!(units.len(), 17);
}

// --- Path discipline -----------------------------------------------------

#[test]
fn traversal_and_shape_escapes_are_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    for path in [
        "/../x",
        "/A/../x",
        "/A/./x",
        "/A/../../x",
        "//x",
        "",
        "relative",
        "./x",
    ] {
        assert!(
            matches!(
                fs.create_dir(path, STAMP),
                Err(Error::Path) | Err(Error::NotFound)
            ),
            "create_dir {path:?}"
        );
        assert!(
            matches!(
                fs.create_dir_all(path, STAMP),
                Err(Error::Path) | Err(Error::NotFound)
            ),
            "create_dir_all {path:?}"
        );
        assert!(
            matches!(
                fs.write_file_all(path, b"x", STAMP),
                Err(Error::Path) | Err(Error::NotFound)
            ),
            "write_file_all {path:?}"
        );
    }
    // The volume is untouched.
    assert_eq!(root_raw(&mem, 2)[0], 0x00);
}

#[test]
fn trailing_slash_is_accepted_for_directories_only() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    fs.create_dir_all("/TRAILING/", STAMP).expect("mkdir -p /");
    fs.create_dir("/SINGLE/", STAMP).expect("mkdir /");
    assert_eq!(fs.kind("/TRAILING"), Ok(Kind::Dir));
    assert_eq!(fs.kind("/SINGLE"), Ok(Kind::Dir));
    // A trailing slash on a *file* path is refused: it names a
    // directory, and a directory cannot be written as a file.
    assert_eq!(
        fs.write_file_all("/TRAILING/", b"x", STAMP),
        Err(Error::NotAFile)
    );
}

#[test]
fn too_many_path_components_is_refused() {
    let mem = Mem::new(image());
    let fs = mount(&mem);
    let mut path = String::new();
    for i in 0..40 {
        path.push_str(&format!("/d{i}"));
    }
    assert_eq!(fs.create_dir_all(&path, STAMP), Err(Error::Path));
    assert_eq!(root_raw(&mem, 2)[0], 0x00, "nothing written");
}

// --- Refusals leave the image byte-identical -----------------------------

#[test]
fn full_disk_mkdir_leaves_the_image_byte_identical() {
    let mut img = image();
    for cluster in 2..=CLUSTERS + 1 {
        fat_set(&mut img, cluster, 0xFFFF); // no free cluster
    }
    let mem = Mem::new(img);
    let before = mem.data.borrow().clone();
    let fs = mount(&mem);
    assert_eq!(fs.create_dir("/NEWDIR", STAMP), Err(Error::NoSpace));
    assert_eq!(fs.create_dir_all("/A/B/C", STAMP), Err(Error::NoSpace));
    assert_eq!(
        fs.write_file_all("/A/B/file.txt", b"x", STAMP),
        Err(Error::NoSpace)
    );
    assert_eq!(*mem.data.borrow(), before, "refusals must not mutate");
}

#[test]
fn no_free_directory_slot_leaves_the_image_byte_identical() {
    let mut img = image();
    for slot in 2..ROOT_ENTRIES {
        root_slot(&mut img, slot, &raw_entry(b"FILLER  ", b"BIN", 0x20, 0, 0));
    }
    let mem = Mem::new(img);
    let before = mem.data.borrow().clone();
    let fs = mount(&mem);
    assert_eq!(fs.create_dir("/NEWDIR", STAMP), Err(Error::NoSpace));
    assert_eq!(*mem.data.borrow(), before);
}

#[test]
fn no_room_for_an_lfn_chain_is_refused() {
    let mut img = image();
    // Exactly one free slot remains (the last root slot): a long name
    // needs its LFN chain plus the 8.3 entry, so it must be refused.
    for slot in 2..ROOT_ENTRIES - 1 {
        root_slot(&mut img, slot, &raw_entry(b"FILLER  ", b"BIN", 0x20, 0, 0));
    }
    let mem = Mem::new(img);
    let before = mem.data.borrow().clone();
    let fs = mount(&mem);
    assert_eq!(
        fs.write_file("/some-long-name.txt", b"x", STAMP),
        Err(Error::NoSpace)
    );
    // A plain 8.3 name still fits in the single free slot.
    assert_eq!(*mem.data.borrow(), before, "refusal must not mutate");
    fs.write_file("/OK.TXT", b"x", STAMP).expect("8.3 fits");
    assert_eq!(read_exact(&fs, "/OK.TXT", 1), b"x");
}

// --- Overwrite + stale LFN consistency -----------------------------------

#[test]
fn overwrite_through_a_long_name_keeps_the_lfn_chain() {
    let mem = Mem::new(image());
    {
        let fs = mount(&mem);
        fs.write_file("/LongNameOverwrite.txt", b"AAAAAAAA", STAMP)
            .expect("create");
    }
    let before: Vec<u8> = mem.data.borrow()
        [ROOT_START as usize * SECTOR..ROOT_START as usize * SECTOR + 3 * 32]
        .to_vec();
    {
        let fs = mount(&mem);
        fs.write_file("/LongNameOverwrite.txt", b"BBBBBBBB", STAMP)
            .expect("overwrite");
    }
    let after: Vec<u8> = mem.data.borrow()
        [ROOT_START as usize * SECTOR..ROOT_START as usize * SECTOR + 3 * 32]
        .to_vec();
    assert_eq!(before, after, "LFN entries and 8.3 name unchanged");
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, "/LongNameOverwrite.txt", 8), b"BBBBBBBB");
    assert_eq!(read_exact(&fs, "/LONGNA~1.TXT", 8), b"BBBBBBBB");
}

#[test]
fn new_long_name_clears_stale_lfn_entries_before_its_run() {
    let mut img = image();
    // Slots 2-3: an orphaned LFN chain; slot 4: its deleted 8.3 entry.
    let stale_units = utf16("GoneLongName.txt");
    let sum = spec_checksum(b"GONEL~1 TXT");
    root_slot(&mut img, 2, &spec_lfn_entry(&stale_units, 2, 2, sum));
    root_slot(&mut img, 3, &spec_lfn_entry(&stale_units, 1, 2, sum));
    root_slot(&mut img, 4, &raw_entry(b"GONEL~1 ", b"TXT", 0x20, 0, 0));
    img[ROOT_START as usize * SECTOR + 4 * 32] = 0xE5;

    let mem = Mem::new(img);
    let fs = mount(&mem);
    assert_eq!(
        fs.read_file("/GoneLongName.txt", &mut [0u8; 4]),
        Err(Error::NotFound)
    );
    // The next multi-slot name starts at the free slot 4 (slots 2-3 are
    // still typed LFN entries, not free), and the clearing pass marks
    // the stale chain deleted so no scan can assemble it.
    fs.write_file("/FreshLongName.txt", b"fresh", STAMP)
        .expect("create");
    assert_eq!(root_raw(&mem, 2)[0], 0xE5, "stale LFN cleared");
    assert_eq!(root_raw(&mem, 3)[0], 0xE5, "stale LFN cleared");
    assert_eq!(root_raw(&mem, 4)[11], 0x0F, "new LFN part");
    assert_eq!(read_exact(&fs, "/FreshLongName.txt", 5), b"fresh");
    assert_eq!(
        fs.read_file("/GoneLongName.txt", &mut [0u8; 4]),
        Err(Error::NotFound)
    );
}

// --- Handcrafted chains (reader direction) -------------------------------

#[test]
fn handcrafted_lfn_chain_reads_and_a_bad_checksum_is_discarded() {
    let mut img = image();
    let name = "HandCraftedName.txt";
    let units = utf16(name);
    let sum = spec_checksum(b"HANDCR~1TXT");
    root_slot(&mut img, 2, &spec_lfn_entry(&units, 2, 2, sum));
    root_slot(&mut img, 3, &spec_lfn_entry(&units, 1, 2, sum));
    root_slot(&mut img, 4, &raw_entry(b"HANDCR~1", b"TXT", 0x20, 6, 5));
    img[cluster_off(6)..cluster_off(6) + 5].copy_from_slice(b"craft");
    fat_set(&mut img, 6, 0xFFFF);
    let mem = Mem::new(img);
    let fs = mount(&mem);
    assert_eq!(read_exact(&fs, &format!("/{name}"), 5), b"craft");
    assert_eq!(read_exact(&fs, "/HANDCR~1.TXT", 5), b"craft");

    // Corrupting one checksum byte makes the reader discard the whole
    // chain: the long name disappears, the 8.3 name still works.
    let mut bad = mem.data.borrow().clone();
    bad[ROOT_START as usize * SECTOR + 2 * 32 + 13] ^= 0xFF;
    let mem2 = Mem::new(bad);
    let fs2 = mount(&mem2);
    assert_eq!(
        fs2.read_file(&format!("/{name}"), &mut [0u8; 5]),
        Err(Error::NotFound)
    );
    assert_eq!(read_exact(&fs2, "/HANDCR~1.TXT", 5), b"craft");
}

// --- The oracle ----------------------------------------------------------

fn xorshift64(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// A randomized tree workload against a model: `create_dir_all` and
/// `write_file_all` over a pool of short, long and Unicode names in a
/// pool of directories. After **every** operation the volume is
/// re-mounted from scratch and every model file is read back byte-exact,
/// every model directory reports [`Kind::Dir`], and the pre-seeded
/// `/README.TXT` stays intact.
#[test]
fn oracle_randomized_tree_matches_a_model() {
    const DIRS: [&str; 7] = [
        "",
        "/A",
        "/B",
        "/A/C",
        "/A/C/Deep",
        "/LongDirectoryName",
        "/B/LongSubName",
    ];
    const FILES: [&str; 8] = [
        "one.txt",
        "two.bin",
        "three.dat",
        "a-really-long-file-name.log",
        "another-long-name.md",
        "niño.txt",
        "emoji-😀.txt",
        "UPPER.TXT",
    ];
    let mem = Mem::new(image());
    let mut model: Vec<(String, Vec<u8>)> = Vec::new();
    let mut dirs: Vec<String> = Vec::new();
    let mut state = 0x2026_1122u64;
    let mut byte = 0u8;

    for i in 0..40usize {
        let dir = DIRS[(xorshift64(&mut state) as usize) % DIRS.len()];
        let name = FILES[(xorshift64(&mut state) as usize) % FILES.len()];
        let len = (xorshift64(&mut state) % 701) as usize; // crosses clusters
        byte = byte.wrapping_add(0x3D).wrapping_add(len as u8);
        let data: Vec<u8> = (0..len).map(|j| (j as u8) ^ byte).collect();
        let path = format!("{dir}/{name}");
        {
            let fs = mount(&mem);
            if !dir.is_empty() {
                fs.create_dir_all(dir, STAMP)
                    .unwrap_or_else(|e| panic!("op {i} mkdir -p {dir}: {e:?}"));
                if !dirs.iter().any(|d| d == dir) {
                    dirs.push(dir.to_string());
                }
            }
            fs.write_file_all(&path, &data, STAMP)
                .unwrap_or_else(|e| panic!("op {i} write {path} len {len}: {e:?}"));
        }
        match model.iter_mut().find(|(p, _)| *p == path) {
            Some(entry) => entry.1 = data,
            None => model.push((path, data)),
        }

        // Fresh mount, then verify everything.
        let fs = mount(&mem);
        for (p, expect) in &model {
            let mut buf = vec![0u8; expect.len()];
            let got = fs
                .read_file(p, &mut buf)
                .unwrap_or_else(|e| panic!("op {i} read {p}: {e:?}"));
            assert_eq!(got, expect.len(), "op {i} size of {p}");
            assert_eq!(&buf[..got], &expect[..], "op {i} content of {p}");
        }
        for d in &dirs {
            assert_eq!(fs.kind(d), Ok(Kind::Dir), "op {i} dir {d}");
        }
        let mut readme = [0u8; 24];
        let n = fs.read_file("/README.TXT", &mut readme).expect("README");
        assert_eq!(&readme[..n], README, "op {i}: README must stay intact");
    }

    // The FAT mirrors never diverge.
    let data = mem.data.borrow();
    let fat0 =
        &data[RESERVED as usize * SECTOR..(RESERVED as usize + FAT_SECTORS as usize) * SECTOR];
    let fat1 = &data[(RESERVED as usize + FAT_SECTORS as usize) * SECTOR
        ..(RESERVED as usize + 2 * FAT_SECTORS as usize) * SECTOR];
    assert_eq!(fat0, fat1, "FAT mirrors diverged");
}
