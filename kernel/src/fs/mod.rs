//! FAT filesystem — installer milestones FS1 (`FAT_OK`) and FS2
//! (`FS_WRITE_OK`).
//!
//! Two halves:
//!
//! - [`AtaDisk`], the block adapter: the ATA driver's sector reads
//!   *and writes* behind `fat::BlockDevice`'s byte-range interface.
//!   Only whole, 512-byte-aligned sectors are accepted (what PIO
//!   `READ SECTORS`/`WRITE SECTORS` can move) and every range is
//!   checked against the drive's IDENTIFY-reported capacity with
//!   `fat::checked_end` before a port is touched — the same contract
//!   the crate's host tests enforce through their `Strict` adapter.
//! - [`prove`], the boot proof: mount the volume, open
//!   `/README.TXT`, compare it byte-for-byte with the constant the
//!   image was written from, print `FAT_OK`; then (FS2) *write*
//!   `/RESULT.TXT`, re-mount from scratch, read it back byte-exact and
//!   re-check `/README.TXT`, print `FS_WRITE_OK`.
//!
//! ## Fail-closed, silent-when-absent
//!
//! With no drive (the main smoke — it runs diskless), `ata::probe`
//! returns `None` and `prove` is never called: **zero output**, so the
//! 22-marker chain stays untouched (AGENTS.md). With a drive present
//! every failure — unparseable BPB, missing file, wrong bytes, short
//! chain, refused write, stale read-back — is a `FATAL: fs: …` line
//! plus `halt()`: `cargo xtask smoke-install` must never pass on a
//! broken filesystem.
//!
//! ## FS2 write proof
//!
//! [`write_proof`] runs only *after* `FAT_OK` and only with a drive:
//! write a known payload, then **re-mount from scratch** — a fresh
//! `AtaDisk` + fresh `fat::Fat16`, so the read-back can only be served
//! from the device, not from any state this function holds (the adapter
//! itself is stateless by design: no cache, write-through — see
//! `fat::write` for the ordering and the explicit *no crash
//! consistency yet* stance). It also re-reads `/README.TXT`: a writer
//! that clobbers its neighbours fails here. No drive → returns before
//! any print, like the rest of `prove`.

use crate::ata;

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

/// The kernel's ATA drive as a `fat::BlockDevice`.
///
/// Deliberately thin (rule of three: two methods beyond capacity, and
/// they are mirrors): `fat` already turns byte ranges into sector
/// transfers through a 512-byte scratch, so the adapter only has to
/// translate "aligned sector range" into `Drive::read_sectors` /
/// `Drive::write_sectors`. Stateless on purpose — no cache, no dirty
/// tracking: `write_at` returning `Ok` means the bytes went to the
/// device (write-through), which is what makes a fresh re-mount a
/// meaningful read-back in [`write_proof`].
struct AtaDisk<'a>(&'a ata::Drive);

impl fat::BlockDevice for AtaDisk<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors) * 512
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
/// Only ever called when `ata::probe` actually found a drive — with no
/// disk attached this function is never reached and boot prints
/// nothing extra.
pub(crate) fn prove(dev: &ata::Drive) {
    let disk = AtaDisk(dev);
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
}

/// FS2's proof (`FS_WRITE_OK`), reached only after `FAT_OK` and only
/// with a drive present (the diskless main smoke never gets here).
///
/// 1. Write `/RESULT.TXT` with a known payload — write-through: the
///    FAT sectors (both mirrors), data sectors and directory entry
///    land on the device inside `write_file`, in `fat::write`'s
///    documented order.
/// 2. **Re-mount from scratch**: a fresh `AtaDisk` over the same drive
///    and a fresh `fat::Fat16` — no state from step 1 survives, so the
///    read-back can only be served from the device.
/// 3. Assert `/RESULT.TXT` byte-exact, then re-read `/README.TXT` and
///    assert it too — a writer that clobbers its neighbour fails here.
fn write_proof(dev: &ata::Drive) {
    // Timestamps come from the CMOS RTC; a dead clock falls back to
    // the crate's documented fixed value (1980-01-01), never a guess.
    let stamp = match crate::rtc::now_epoch() {
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
    };

    // Step 1: the write (fresh mount — `/RESULT.TXT` may exist from a
    // previous run of the same image; `write_file` overwrites it).
    {
        let disk = AtaDisk(dev);
        let fs = match fat::Fat16::mount(&disk) {
            Ok(fs) => fs,
            Err(e) => fatal(e),
        };
        if let Err(e) = fs.write_file(RESULT_PATH, RESULT_PAYLOAD, stamp) {
            fatal(e);
        }
    }

    // Steps 2+3: re-mount and read back, byte for byte.
    let disk = AtaDisk(dev);
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

/// Fail-closed: name the refusal and stop the machine, so a broken
/// filesystem can never look like a passing installer smoke.
fn fatal(e: fat::Error) -> ! {
    serial_println!("FATAL: fs: {:?}", e);
    crate::halt()
}
