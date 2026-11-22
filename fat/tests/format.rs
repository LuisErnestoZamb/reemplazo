//! Host tests for the shared FAT16 formatter (`fat::format`) — the
//! geometry selector, the boot-sector contract with `Fat16::mount`,
//! and the refusals. The kernel's installer and xtask's disk images
//! both format through this code, so these tests gate both.

use std::cell::RefCell;

use fat::{BlockDevice, Error, Fat16, FormatOpts, format_fat16, geometry};

/// Strict in-memory device (same contract as the kernel's ATA
/// adapter): aligned whole sectors, range-checked both directions.
struct Mem(RefCell<Vec<u8>>);

impl Mem {
    fn new(len: usize) -> Self {
        Self(RefCell::new(vec![0u8; len]))
    }

    fn boot_sector(&self) -> [u8; 512] {
        let data = self.0.borrow();
        let mut sector = [0u8; 512];
        sector.copy_from_slice(&data[..512]);
        sector
    }
}

impl BlockDevice for Mem {
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

/// Read-only device (default `write_at` → `ReadOnly`).
struct ReadOnly;

impl BlockDevice for ReadOnly {
    fn size_bytes(&self) -> u64 {
        8 * 1024 * 1024
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), Error> {
        let _ = (offset, buf);
        Err(Error::Read)
    }
}

fn opts<'a>(label: &'a [u8; 11], hidden: u32) -> FormatOpts<'a> {
    FormatOpts {
        label,
        volume_id: 0x2026_1122,
        hidden_sectors: hidden,
        min_sectors_per_cluster: 1,
    }
}

// --- geometry() ---------------------------------------------------------

#[test]
fn geometry_64mib_superfloppy() {
    // 64 MiB = 131072 sectors: spc=1 overflows the FAT16 window, so
    // spc=2 wins — every number pinned here is re-asserted against a
    // real formatted image below.
    let geo = geometry(131_072).expect("64 MiB is FAT16");
    assert_eq!(geo.sectors_per_cluster, 2);
    assert_eq!(geo.fat_sectors, 257);
    assert_eq!(geo.clusters, 65_262);
    assert_eq!(geo.data_start_sector, 547);
    assert_eq!(geo.total_sectors, 131_072);
}

#[test]
fn geometry_partition_sized_slice() {
    // The installer's p2 on a 64 MiB target (126943 sectors — see
    // docs/installer.md §3.2's layout): spc=2, inside the window.
    let geo = geometry(126_943).expect("p2 is FAT16");
    assert_eq!(geo.sectors_per_cluster, 2);
    assert_eq!(geo.fat_sectors, 248);
    assert_eq!(geo.clusters, 63_207);
    assert_eq!(geo.data_start_sector, 529);
}

#[test]
fn geometry_small_device_uses_one_sector_clusters() {
    let geo = geometry(16_384).expect("8 MiB is FAT16");
    assert_eq!(geo.sectors_per_cluster, 1);
    assert_eq!(geo.clusters, 16_221);
}

#[test]
fn geometry_large_device_uses_max_clusters() {
    // ~1.9 GiB: only 32 KiB clusters fit under the window.
    let geo = geometry(4_000_000).expect("FAT16 at 64 spc");
    assert_eq!(geo.sectors_per_cluster, 64);
    assert!(geo.clusters <= 65_524);
}

#[test]
fn geometry_refusals() {
    assert_eq!(geometry(0), Err(Error::TooSmall));
    // 1 MiB: even 512 B clusters cannot reach 4085 clusters.
    assert_eq!(geometry(2_048), Err(Error::TooSmall));
    // Past what 32 KiB clusters can hold under 65524 → not FAT16.
    assert_eq!(geometry(5_000_000), Err(Error::NotFat16));
    // Absurd totals (past FAT's 32-bit total field) stay refused too.
    assert_eq!(geometry(u32::MAX), Err(Error::NotFat16));
}

// --- format_fat16 -------------------------------------------------------

#[test]
fn format_64mib_boots_and_round_trips_a_file() {
    let img = Mem::new(64 * 1024 * 1024);
    let geo = format_fat16(&img, &opts(b"REEMPLAZO  ", 0)).expect("formats");
    assert_eq!(geo.sectors_per_cluster, 2);

    // Boot-sector contract (what `Fat16::mount` and GRUB's fat.mod
    // read): jump, OEM, BPB fields, label, type string, signature.
    let boot = img.boot_sector();
    assert_eq!(&boot[0..11], b"\xEB<\x90MSDOS5.0");
    assert_eq!(u16::from_le_bytes([boot[11], boot[12]]), 512);
    assert_eq!(boot[13], 2);
    assert_eq!(boot[16], 2); // FAT count
    assert_eq!(u16::from_le_bytes([boot[17], boot[18]]), 512); // root entries
    assert_eq!(boot[21], 0xF8); // media
    assert_eq!(
        u16::from_le_bytes([boot[22], boot[23]]),
        geo.fat_sectors as u16
    );
    assert_eq!(&boot[43..54], b"REEMPLAZO  ");
    assert_eq!(&boot[54..62], b"FAT16   ");
    assert_eq!(
        u32::from_le_bytes([boot[32], boot[33], boot[34], boot[35]]),
        131_072
    );
    assert_eq!([boot[510], boot[511]], [0x55, 0xAA]);

    // FAT[2] is free after formatting (cluster 2 belongs to nobody
    // yet). The adapter speaks whole sectors, so read the FAT's first
    // sector and slice the entry out of it.
    let mut fat0 = [0u8; 512];
    img.read_at(512, &mut fat0).expect("fat read");
    assert_eq!(&fat0[0..4], &[0xF8, 0xFF, 0xFF, 0xFF]); // entries 0/1
    assert_eq!(&fat0[4..6], &[0x00, 0x00]); // cluster 2 free

    // The real round-trip: mount (the formatter's own self-check did
    // this too), write a file, re-mount from scratch, read it back.
    let payload = b"reemplazo installer payload\n";
    {
        let fs = Fat16::mount(&img).expect("mounts");
        fs.write_file("/PAYLOAD.TXT", payload, fat::Stamp::FAT_EPOCH)
            .expect("writes");
    }
    let fs = Fat16::mount(&img).expect("re-mounts");
    let mut buf = [0u8; 64];
    let n = fs.read_file("/PAYLOAD.TXT", &mut buf).expect("reads");
    assert_eq!(&buf[..n], payload);
}

#[test]
fn format_inside_a_partition_records_hidden_sectors() {
    // Formatting a slice with hidden=4096 (the p2 start LBA the
    // installer passes): the BPB must carry it.
    let full = Mem::new(8 * 1024 * 1024);
    let geo = format_fat16(&full, &opts(b"REEMPLAZO  ", 4096)).expect("formats");
    assert_eq!(geo.total_sectors, 16_384);
    let boot = full.boot_sector();
    assert_eq!(
        u32::from_le_bytes([boot[28], boot[29], boot[30], boot[31]]),
        4096
    );
}

#[test]
fn format_honors_min_cluster_size() {
    // The installer's knob: min 16 sectors/cluster (8 KiB) on 64 MiB
    // — spc jumps straight to 16, the volume still mounts, and a file
    // round-trips.
    let img = Mem::new(64 * 1024 * 1024);
    let opts = FormatOpts {
        label: b"REEMPLAZO  ",
        volume_id: 0x2026_1122,
        hidden_sectors: 0,
        min_sectors_per_cluster: 16,
    };
    let geo = format_fat16(&img, &opts).expect("formats");
    assert_eq!(geo.sectors_per_cluster, 16);
    assert!(geo.clusters >= 4085 && geo.clusters <= 65524);
    let boot = img.boot_sector();
    assert_eq!(boot[13], 16);

    let fs = Fat16::mount(&img).expect("mounts");
    fs.write_file("/PAYLOAD.BIN", b"min-spc ok", fat::Stamp::FAT_EPOCH)
        .expect("writes");
    let mut buf = [0u8; 16];
    let n = fs.read_file("/PAYLOAD.BIN", &mut buf).expect("reads");
    assert_eq!(&buf[..n], b"min-spc ok");
}

#[test]
fn geometry_refuses_non_power_of_two_min_cluster() {
    use fat::geometry_with;
    assert_eq!(geometry_with(131_072, 0), Err(Error::BadSectorsPerCluster));
    assert_eq!(geometry_with(131_072, 3), Err(Error::BadSectorsPerCluster));
    assert_eq!(
        geometry_with(131_072, 128),
        Err(Error::BadSectorsPerCluster)
    );
    // A bound that cannot land in the window still fails honestly:
    // min 64 on 8 MiB leaves far fewer than 4085 clusters.
    assert_eq!(geometry_with(16_384, 64), Err(Error::TooSmall));
}

#[test]
fn format_refusals() {
    // Not a whole number of sectors / too small.
    assert_eq!(
        format_fat16(&Mem::new(8 * 1024 * 1024 + 1), &opts(b"REEMPLAZO  ", 0)),
        Err(Error::TooSmall)
    );
    assert_eq!(
        format_fat16(&Mem::new(1024 * 1024), &opts(b"REEMPLAZO  ", 0)),
        Err(Error::TooSmall)
    );
    // Non-printable label bytes are refused, never mangled.
    let mut bad = *b"REEMPLAZO  ";
    bad[3] = 0x01;
    assert_eq!(
        format_fat16(&Mem::new(8 * 1024 * 1024), &opts(&bad, 0)),
        Err(Error::InvalidName)
    );
    // A device without write support fails on the very first write.
    assert_eq!(
        format_fat16(&ReadOnly, &opts(b"REEMPLAZO  ", 0)),
        Err(Error::ReadOnly)
    );
}
