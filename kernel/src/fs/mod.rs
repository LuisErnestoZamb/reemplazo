//! FAT filesystem — installer milestones FS1 (`FAT_OK`), FS2
//! (`FS_WRITE_OK`) and FS3 (`FS_TREE_OK`), plus the full-tree git
//! checkout write target (`GIT_CHECKOUT_OK`).
//!
//! Four pieces:
//!
//! - [`BlockDisk`], the block adapter: the block layer's sector reads
//!   *and writes* behind `fat::BlockDevice`'s byte-range interface —
//!   `ata::Disk`, which is either the legacy-IDE PIO drive or an
//!   AHCI/SATA disk (`crate::ahci`), with one identical contract. Only
//!   whole, 512-byte-aligned sectors are accepted (what
//!   `READ SECTORS`/`WRITE SECTORS` and AHCI `READ/WRITE DMA EXT` can
//!   move) and every range is checked against the device's
//!   IDENTIFY-reported capacity with `fat::checked_end` before a
//!   command is issued — the same contract the crate's host tests
//!   enforce through their `Strict` adapter.
//! - [`prove`], the boot proof: mount the volume, open
//!   `/README.TXT`, compare it byte-for-byte with the constant the
//!   image was written from, print `FAT_OK`; then (FS2) *write*
//!   `/RESULT.TXT`, re-mount from scratch, read it back byte-exact and
//!   re-check `/README.TXT`, print `FS_WRITE_OK`; then (FS3) create a
//!   nested long-name tree, re-mount and read it back, print
//!   `FS_TREE_OK`.
//! - [`checkout_tree`] + [`read_back`], G3/G4's disk write target:
//!   write the fetched repo's **whole** tree (directories created as
//!   needed, long names through the LFN writer), then re-mount and read
//!   back a root file and a nested file (the `GIT_CHECKOUT_OK` proof in
//!   `crate::git_fetch`).
//!
//! ## Fail-closed, silent-when-absent
//!
//! With no drive (the main smoke — it runs diskless), `ata::probe` and
//! `ahci::probe` return `None` and `prove` is never called: **zero
//! output**, so the main smoke's marker chain stays untouched
//! (AGENTS.md). With a drive present every failure — unparseable BPB, missing file, wrong bytes,
//! short chain, refused write, stale read-back — is a `FATAL: fs: …`
//! line plus `halt()`: `cargo xtask smoke-install` must never pass on a
//! broken filesystem.
//!
//! ## FS2 write proof
//!
//! [`write_proof`] runs only *after* `FAT_OK` and only with a drive:
//! write a known payload, then **re-mount from scratch** — a fresh
//! `BlockDisk` + fresh `fat::Fat16`, so the read-back can only be served
//! from the device, not from any state this function holds (the adapter
//! itself is stateless by design: no cache, write-through — see
//! `fat::write` for the ordering and the explicit *no crash
//! consistency yet* stance). It also re-reads `/README.TXT`: a writer
//! that clobbers its neighbours fails here. No drive → returns before
//! any print, like the rest of `prove`.
//!
//! ## FS3 tree proof
//!
//! [`tree_proof`] runs after `FS_WRITE_OK`: `write_file_all` creates
//! `/sub/dir/deep/nested-long-name-file.txt` (three missing
//! directories, a long name behind an LFN chain) and
//! `/SUB/DIR/PLAIN.TXT` (the same directories through mixed-case
//! 8.3 lookups); a fresh mount reads both back byte-exact and re-checks
//! the FS2 payloads.

use crate::ata;
use alloc::vec::Vec;

/// Files are read in a fixed buffer sized to the expected content —
/// `prove`'s proof is "exactly these bytes", so anything larger is a
/// failure ([`fat::Error::BufferTooSmall`]) rather than a truncated
/// pass.
const README_PATH: &str = "/README.TXT";

/// `/README.TXT`'s exact content. Duplicated in xtask's
/// `write_disk_image` (host crates cannot depend on the kernel) — the
/// two are the contract this proof checks.
const README_EXPECTED: &[u8] = b"reemplazo filesystem ok\n";

/// The file FS2 writes in its proof, and its exact payload — also the
/// bytes the read-back must reproduce byte-for-byte.
const RESULT_PATH: &str = "/RESULT.TXT";
const RESULT_PAYLOAD: &[u8] = b"reemplazo fs write ok\n";

/// FS3's tree proof: a long-named file three directories deep, and the
/// same directories through mixed-case 8.3 lookups. Content is
/// distinctive so a truncated or zeroed read-back cannot pass.
const TREE_LONG_PATH: &str = "/sub/dir/deep/nested-long-name-file.txt";
const TREE_LONG_CONTENT: &[u8] = b"reemplazo fs tree ok: nested long name\n";
const TREE_83_PATH: &str = "/SUB/DIR/PLAIN.TXT";
const TREE_83_CONTENT: &[u8] = b"reemplazo fs tree ok: nested 8.3\n";

/// Longest UTF-8 path the checkout builds (the git walk caps paths at
/// 255 bytes; this leaves room for the leading `/`).
const TREE_PATH_CAP: usize = 512;

/// The kernel's ATA drive as a `fat::BlockDevice`.
///
/// Deliberately thin (rule of three: two methods beyond capacity, and
/// they are mirrors): `fat` already turns byte ranges into sector
/// transfers through a 512-byte scratch, so the adapter only has to
/// translate "aligned sector range" into `Drive::read_sectors` /
/// `Drive::write_sectors`. Stateless on purpose — no cache, no dirty
/// tracking: `write_at` returning `Ok` means the bytes went to the
/// device (write-through), which is what makes a fresh re-mount a
/// meaningful read-back in [`write_proof`]. `pub(crate)` so
/// `crate::install` mounts the *source* volume through the same
/// adapter when copying the payload.
pub(crate) struct BlockDisk<'a>(pub(crate) &'a ata::Disk);

impl fat::BlockDevice for BlockDisk<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors()) * 512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        // PIO moves whole sectors only; the filesystem layer always
        // asks for exactly that, so anything else is a bug on *our*
        // side of the boundary (refused, not silently rounded).
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.size_bytes(), offset, buf.len())?;
        let lba = u32::try_from(offset / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Read)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), fat::Error> {
        // Same contract as `read_at`: whole sectors only, range-checked
        // against the IDENTIFY-reported capacity (which `write_sectors`
        // re-checks on the device side — both ends fail closed).
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.size_bytes(), offset, buf.len())?;
        let lba = u32::try_from(offset / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.write_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Write)
        }
    }
}

/// Mount the volume on `dev`, read `/README.TXT` and check it
/// byte-for-byte; print `FAT_OK` on success — then (FS2) run
/// [`write_proof`] for `FS_WRITE_OK`.
///
/// Only ever called when `ata::probe` (or the AHCI fallback) actually
/// found a marked drive — with no disk attached this function is never
/// reached and boot prints nothing extra.
pub(crate) fn prove(dev: &ata::Disk) {
    let disk = BlockDisk(dev);
    let fs = match fat::Fat16::mount(&disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };

    let mut buf = [0u8; README_EXPECTED.len()];
    let n = match fs.read_file(README_PATH, &mut buf) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };

    // Exact content, both directions: a short file leaves `n` short, a
    // long one was already refused as `BufferTooSmall`.
    if n != README_EXPECTED.len() || buf[..n] != *README_EXPECTED {
        serial_println!(
            "FATAL: fs: {} is {} bytes, expected exactly {}",
            README_PATH,
            n,
            README_EXPECTED.len()
        );
        crate::halt();
    }

    serial_println!("FAT_OK"); // machine-checked by `cargo xtask smoke-install`

    write_proof(dev); // FS_WRITE_OK — or `FATAL: fs:` + halt
    tree_proof(dev); // FS_TREE_OK  — or `FATAL: fs:` + halt
}

/// The timestamp writes get: the CMOS RTC when it answers, the crate's
/// documented fixed value (`1980-01-01`) when it does not — this code
/// never invents a clock. Shared by [`write_proof`] (FS2) and
/// `crate::install`'s payload copy (I1), so both write paths stamp
/// identically.
pub(crate) fn stamp() -> fat::Stamp {
    match crate::rtc::now_epoch() {
        Some(epoch) => {
            let clock = crate::rtc::from_epoch(epoch);
            fat::Stamp {
                year: clock.year,
                month: clock.month,
                day: clock.day,
                hour: clock.hour,
                minute: clock.minute,
                second: clock.second,
            }
        }
        None => fat::Stamp::FAT_EPOCH,
    }
}

/// FS2's proof (`FS_WRITE_OK`), reached only after `FAT_OK` and only
/// with a drive present (the diskless main smoke never gets here).
///
/// 1. Write `/RESULT.TXT` with a known payload — write-through: the
///    FAT sectors (both mirrors), data sectors and directory entry
///    land on the device inside `write_file`, in `fat::write`'s
///    documented order.
/// 2. **Re-mount from scratch**: a fresh `BlockDisk` over the same drive
///    and a fresh `fat::Fat16` — no state from step 1 survives, so the
///    read-back can only be served from the device.
/// 3. Assert `/RESULT.TXT` byte-exact, then re-read `/README.TXT` and
///    assert it too — a writer that clobbers its neighbour fails here.
fn write_proof(dev: &ata::Disk) {
    // Timestamps come from the CMOS RTC; a dead clock falls back to
    // the crate's documented fixed value (1980-01-01), never a guess.
    let stamp = stamp();

    // Step 1: the write (fresh mount — `/RESULT.TXT` may exist from a
    // previous run of the same image; `write_file` overwrites it).
    {
        let disk = BlockDisk(dev);
        let fs = match fat::Fat16::mount(&disk) {
            Ok(fs) => fs,
            Err(e) => fatal(e),
        };
        if let Err(e) = fs.write_file(RESULT_PATH, RESULT_PAYLOAD, stamp) {
            fatal(e);
        }
    }

    // Steps 2+3: re-mount and read back, byte for byte.
    let disk = BlockDisk(dev);
    let fs = match fat::Fat16::mount(&disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };

    let mut buf = [0u8; RESULT_PAYLOAD.len()];
    let n = match fs.read_file(RESULT_PATH, &mut buf) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    if n != RESULT_PAYLOAD.len() || buf[..n] != *RESULT_PAYLOAD {
        serial_println!(
            "FATAL: fs: {} read back {} bytes, expected exactly {}",
            RESULT_PATH,
            n,
            RESULT_PAYLOAD.len()
        );
        crate::halt();
    }

    // Neighbour check: the write must not have touched README.
    let mut readme = [0u8; README_EXPECTED.len()];
    let n = match fs.read_file(README_PATH, &mut readme) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    if n != README_EXPECTED.len() || readme[..n] != *README_EXPECTED {
        serial_println!(
            "FATAL: fs: {} clobbered by the write proof ({} bytes)",
            README_PATH,
            n
        );
        crate::halt();
    }

    serial_println!("FS_WRITE_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// FS3's proof (`FS_TREE_OK`), reached only after `FS_WRITE_OK`.
///
/// 1. `write_file_all` creates `/sub/dir/deep/nested-long-name-file.txt`
///    (three missing directories in one call, the file name long enough
///    to need an LFN chain) and `/SUB/DIR/PLAIN.TXT` (a plain 8.3 name
///    reached through case-insensitive lookups of the same three
///    directories).
/// 2. A **fresh** mount (new `BlockDisk`, new `fat::Fat16`) reads both
///    back byte-exact and re-checks the FS2 payloads — so the bytes can
///    only come from the device.
fn tree_proof(dev: &ata::Disk) {
    let stamp = stamp();
    {
        let disk = BlockDisk(dev);
        let fs = mount_or_fatal(&disk);
        if let Err(e) = fs.write_file_all(TREE_LONG_PATH, TREE_LONG_CONTENT, stamp) {
            fatal(e);
        }
        if let Err(e) = fs.write_file_all(TREE_83_PATH, TREE_83_CONTENT, stamp) {
            fatal(e);
        }
    }

    let disk = BlockDisk(dev);
    let fs = mount_or_fatal(&disk);
    read_check(&fs, TREE_LONG_PATH, TREE_LONG_CONTENT);
    read_check(&fs, TREE_83_PATH, TREE_83_CONTENT);
    // The FS2 payloads and the original image file are still intact.
    read_check(&fs, RESULT_PATH, RESULT_PAYLOAD);
    read_check(&fs, README_PATH, README_EXPECTED);

    // The directories exist as directories: a file read must refuse.
    for dir in ["/sub", "/sub/dir", "/sub/dir/deep", "/SUB/DIR"] {
        match fs.kind(dir) {
            Ok(fat::Kind::Dir) => {}
            Ok(fat::Kind::File) => {
                serial_println!("FATAL: fs: {dir} is a file, expected a directory");
                crate::halt();
            }
            Err(e) => fatal(e),
        }
    }

    serial_println!("FS_TREE_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// Mount a fresh volume over `disk`, or `FATAL: fs:` + halt.
fn mount_or_fatal<'a>(disk: &'a BlockDisk<'a>) -> fat::Fat16<'a, BlockDisk<'a>> {
    match fat::Fat16::mount(disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    }
}

/// Read `path` and require exactly `expected`; any short read, longer
/// file or byte difference is a `FATAL: fs:` line plus halt.
fn read_check<D: fat::BlockDevice + ?Sized>(fs: &fat::Fat16<'_, D>, path: &str, expected: &[u8]) {
    let mut buf = [0u8; 256];
    let slot = match buf.get_mut(..expected.len()) {
        Some(slot) => slot,
        // Every proof payload above is far below 256 bytes; a caller
        // that outgrows the buffer is a bug, refused rather than
        // truncated.
        None => {
            serial_println!("FATAL: fs: {path}: expected content exceeds the proof buffer");
            crate::halt();
        }
    };
    let n = match fs.read_file(path, slot) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    if n != expected.len() || slot != expected {
        serial_println!(
            "FATAL: fs: {path} read back {n} bytes, expected exactly {}",
            expected.len()
        );
        crate::halt();
    }
}

/// Write the fetched repo's **whole** tree into the FAT16 volume
/// (milestone FS3/G4): one mount, one `write_file_all` per blob —
/// directories are created as needed (`mkdir -p` semantics) and long
/// names go through the LFN writer — returning `(written, skipped)`.
/// `skipped` counts names this crate still cannot represent: a path
/// longer than [`TREE_PATH_CAP`], invalid UTF-8 (git tree names are
/// bytes), or a `fat::Error::Path`/`InvalidName`/`NameConflict` refusal.
/// Every other failure (mount, I/O, disk full) is `FATAL: fs:` — a
/// checkout that silently drops a write would be a lying checkout.
pub(crate) fn checkout_tree(dev: &ata::Disk, files: &[(Vec<u8>, &[u8])]) -> (usize, usize) {
    let stamp = stamp();
    let disk = BlockDisk(dev);
    let fs = mount_or_fatal(&disk);
    let (mut written, mut skipped) = (0usize, 0usize);
    let mut path = [0u8; TREE_PATH_CAP];
    for (name, data) in files {
        let Some(len) = name.len().checked_add(1) else {
            skipped += 1;
            continue;
        };
        if len > path.len() {
            skipped += 1;
            continue;
        }
        path[0] = b'/';
        let Some(dst) = path.get_mut(1..len) else {
            skipped += 1;
            continue;
        };
        dst.copy_from_slice(name);
        let path_str = match core::str::from_utf8(&path[..len]) {
            Ok(path) => path,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };
        match fs.write_file_all(path_str, data, stamp) {
            Ok(()) => written += 1,
            Err(fat::Error::InvalidName)
            | Err(fat::Error::NameConflict)
            | Err(fat::Error::Path) => skipped += 1,
            Err(e) => fatal(e),
        }
    }
    (written, skipped)
}

/// Re-mount from scratch and read `path` back into `out` (the G3
/// checkout proof). A fresh mount means the bytes can only come from
/// the device; any failure is `FATAL: fs:`.
pub(crate) fn read_back(dev: &ata::Disk, path: &str, out: &mut [u8]) -> usize {
    let disk = BlockDisk(dev);
    let fs = match fat::Fat16::mount(&disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };
    match fs.read_file(path, out) {
        Ok(n) => n,
        Err(e) => fatal(e),
    }
}

/// Fail-closed: name the refusal and stop the machine, so a broken
/// filesystem can never look like a passing installer smoke.
fn fatal(e: fat::Error) -> ! {
    serial_println!("FATAL: fs: {:?}", e);
    crate::halt()
}
