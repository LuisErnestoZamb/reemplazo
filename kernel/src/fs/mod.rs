//! Read-only FAT filesystem — installer milestone FS1 (`FAT_OK`).
//!
//! Two halves:
//!
//! - [`AtaDisk`], the block adapter: the ATA driver's sector reads
//!   behind `fat::BlockDevice`'s byte-range reads. Only whole,
//!   512-byte-aligned sectors are accepted (what PIO `READ SECTORS`
//!   can move) and every range is checked against the drive's
//!   IDENTIFY-reported capacity with `fat::checked_end` before a port
//!   is touched — the same contract the crate's host tests enforce
//!   through their `Strict` adapter.
//! - [`prove`], the boot proof: mount the volume, open
//!   `/README.TXT`, compare it byte-for-byte with the constant the
//!   image was written from, and print `FAT_OK`.
//!
//! ## Fail-closed, silent-when-absent
//!
//! With no drive (the main smoke — it runs diskless), `ata::probe`
//! returns `None` and `prove` is never called: **zero output**, so the
//! 21-marker chain stays untouched (AGENTS.md). With a drive present
//! every failure — unparseable BPB, missing file, wrong bytes, short
//! chain — is a `FATAL: fs: …` line plus `halt()`: `cargo xtask
//! smoke-install` must never pass on a broken filesystem.

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

/// The kernel's ATA drive as a `fat::BlockDevice`.
///
/// Deliberately thin (rule of three: one method beyond capacity):
/// `fat` already turns byte ranges into sector reads through a 512-byte
/// scratch, so the adapter only has to translate "aligned sector range"
/// into `Drive::read_sectors`.
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
}

/// Mount the volume on `dev`, read `/README.TXT` and check it
/// byte-for-byte; print `FAT_OK` on success.
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
}

/// Fail-closed: name the refusal and stop the machine, so a broken
/// filesystem can never look like a passing installer smoke.
fn fatal(e: fat::Error) -> ! {
    serial_println!("FATAL: fs: {:?}", e);
    crate::halt()
}
