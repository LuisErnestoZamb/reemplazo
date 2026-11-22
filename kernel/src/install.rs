//! Milestone **I1** (docs/installer.md §3.2, §4, §8): the
//! install-to-disk flow, proven by `INST_OK`.
//!
//! Given the *source* disk (the FS1/FS2 volume — already proven by
//! `crate::fs::prove`) and a *target* disk found by
//! [`ata::probe_target`], the flow is exactly docs/installer.md's
//! layout and ordering:
//!
//! 1. **GPT** — protective MBR + primary/backup headers with CRC32
//!    (the `gptwire` crate, adversarially host-tested), p1 =
//!    `bios_grub` 1 MiB @ 1 MiB, p2 = Microsoft Basic Data taking the
//!    rest of the disk (§3.2's table), then **re-read and validated
//!    through the same parser** — so `INST_OK` asserts what landed on
//!    the device, not what we meant to write.
//! 2. **Format p2 FAT16** — `fat::format_fat16`, the formatter shared
//!    with xtask's disk images (one implementation, one contract,
//!    host-tested in `fat/tests/format.rs`).
//! 3. **Copy the payload** — `/README.TXT` + `/RESULT.TXT` read from
//!    the source volume (the FS1 machinery) into a fixed
//!    [`PAYLOAD_CAP`]-sized buffer and written to p2.
//! 4. **Verify** — re-mount p2 from scratch (fresh `Part` + fresh
//!    `fat::Fat16`, no state from the write surviving) and read both
//!    files back byte-exact against the bytes read from the source.
//!
//! ## Neutrality (diskless boots stay silent)
//!
//! `prove` is only reached when `ata::probe` found the source disk
//! (the main smoke has no disk at all), and its *first* action is
//! [`ata::probe_target`]: no second disk, or a second disk without
//! the `reemplazo-target-v1` marker → **`return`, zero output** —
//! `cargo xtask smoke`'s marker chain is untouched, and an unmarked
//! real disk is never wiped (fail-closed; the guided `install <id>`
//! shell builtin of docs/installer.md §7.1 is the future path for
//! unmarked hardware). With a target present, every failure is a
//! loud `FATAL: install: …` + `halt()` — the smoke can never pass on
//! a half-written disk.
//!
//! ## What I1 deliberately does *not* do (I1b / later milestones)
//!
//! - **No GRUB boot code on the target** (`boot.img` → LBA0,
//!   `core.img` → p1): the artifacts live on the ISO
//!   (`/boot/grub/{boot,core}.img`) but the kernel has no ISO9660
//!   reader and no multiboot2-module payload path yet (docs milestone
//!   `MOD_OK`) — there is no honest way for the kernel to *have* the
//!   bytes in this milestone, so the installed disk is not yet
//!   bootable. Deferred to I1b with the payload-delivery milestone,
//!   never faked: `INST_OK` asserts only the four steps above.
//! - No shell `disks`/`install` builtins (boot-time proof chosen for
//!   I1 — see docs/installer.md §8.3), no AHCI, no reboot-from-disk
//!   assert (needs GRUB first).

use crate::ata;
use crate::fs::{AtaDisk, stamp};
use gptwire::{Guid, Partition, TYPE_BASIC_DATA, TYPE_BIOS_GRUB};

/// p1 starts at 1 MiB and spans 1 MiB — docs/installer.md §3.2's
/// `bios_grub` row (1 MiB holds `core.img` ≈172 KB with margin; the
/// GRUB manual asks for ≥31 KiB, 1 MiB recommended).
const P1_FIRST_LBA: u64 = 2048;
const P1_LAST_LBA: u64 = 4095;
/// p2 starts at 2 MiB; its last LBA is *not* a constant here — it
/// comes from [`gptwire::usable_range`], the same function the writer
/// uses, so writer and installer cannot disagree.
const P2_FIRST_LBA: u64 = 4096;
/// Refuse anything smaller than this: GPT's fixed layout needs 34
/// sectors of bookkeeping at each end, and p2 must reach FAT16's
/// 4085-cluster window at 512 B/cluster (≈4218 sectors). 16384
/// sectors (8 MiB) leaves comfortable margin; the smoke's target is
/// 64 MiB.
const MIN_TARGET_SECTORS: u64 = 16_384;
/// Byte cap per copied file — the buffer [`prove`] reads into. Bigger
/// payloads are *refused* (`fat::Error::BufferTooSmall`), never
/// truncated, so a lying directory entry can't overrun anything.
const PAYLOAD_CAP: usize = 4096;
/// The payload: read from the source volume (FS1 proven these exact
/// bytes), written to p2, read back byte-exact.
const PAYLOAD: [&str; 2] = ["/README.TXT", "/RESULT.TXT"];
/// Installed volume's label/id — fixed, so installs are
/// byte-reproducible (v1 stance, `gptwire`'s docs say the same about
/// the GUIDs).
const VOLUME_LABEL: [u8; 11] = *b"REEMPLAZO  ";
const VOLUME_ID: u32 = 0x2026_1122;
/// Fixed GUIDs (v1: deterministic; per-install randomness is future
/// work — documented in `gptwire`).
const DISK_GUID: Guid = Guid::from_bytes([0xA5; 16]);
const P1_UNIQUE_GUID: Guid = Guid::from_bytes([0xB1; 16]);
const P2_UNIQUE_GUID: Guid = Guid::from_bytes([0xB2; 16]);

/// Whole-disk adapter for `gptwire` — sector reads/writes straight
/// through the ATA driver, same contract as `fs::AtaDisk` (aligned
/// whole sectors, range-checked against IDENTIFY capacity on *both*
/// ends: this adapter checks the request, `Drive::*_sectors` re-checks
/// it device-side).
struct GptDev<'a>(&'a ata::Drive);

impl gptwire::Device for GptDev<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors) * 512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), gptwire::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(gptwire::Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(gptwire::Error::OutOfRange)?;
        if end > self.size_bytes() {
            return Err(gptwire::Error::OutOfRange);
        }
        let lba = u32::try_from(offset / 512).map_err(|_| gptwire::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(gptwire::Error::Read)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), gptwire::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(gptwire::Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(gptwire::Error::OutOfRange)?;
        if end > self.size_bytes() {
            return Err(gptwire::Error::OutOfRange);
        }
        let lba = u32::try_from(offset / 512).map_err(|_| gptwire::Error::OutOfRange)?;
        if self.0.write_sectors(lba, buf) {
            Ok(())
        } else {
            Err(gptwire::Error::Write)
        }
    }
}

/// One GPT partition as a `fat::BlockDevice`: byte offsets are
/// partition-relative, every range checked against the window with
/// `fat::checked_end` before the LBA is computed (and the drive
/// re-checks against IDENTIFY capacity, `Drive::*_sectors`' bound).
struct Part<'a>(
    &'a ata::Drive,
    /* first byte */ u64,
    /* bytes */ u64,
);

impl fat::BlockDevice for Part<'_> {
    fn size_bytes(&self) -> u64 {
        self.2
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.2, offset, buf.len())?;
        let abs = self.1.checked_add(offset).ok_or(fat::Error::OutOfRange)?;
        let lba = u32::try_from(abs / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Read)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.2, offset, buf.len())?;
        let abs = self.1.checked_add(offset).ok_or(fat::Error::OutOfRange)?;
        let lba = u32::try_from(abs / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.write_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Write)
        }
    }
}

/// The window describing p2 on `target` — one value built from the
/// validated GPT and reused for format, copy and verify (so all three
/// steps address the *same* byte range by construction).
fn p2_window(target: &ata::Drive, first_lba: u64, last_lba: u64) -> Part<'_> {
    let bytes = (last_lba - first_lba + 1) * 512;
    Part(target, first_lba * 512, bytes)
}

/// Run the I1 install (see module docs). Silent without a marked
/// target disk; `FATAL:` + `halt()` on any failure with one.
pub(crate) fn prove(source: &ata::Drive) {
    let Some(target) = ata::probe_target(source.unit()) else {
        return; // no (marked) target disk → zero output, boot continues
    };

    let total = u64::from(target.sectors);
    if total < MIN_TARGET_SECTORS {
        serial_println!(
            "FATAL: install: target too small ({total} sectors, need {MIN_TARGET_SECTORS})"
        );
        crate::halt();
    }
    let mut name_buf = [0u8; 40];
    let model = target.model_name(&mut name_buf);
    serial_println!(
        "install: target '{model}' {total} sectors ({} MiB)",
        total / 2048
    );

    // --- Step 1: GPT (docs/installer.md §3.2) ---
    let Some((_, last_usable)) = gptwire::usable_range(total * 512) else {
        fatal_msg("target cannot hold a GPT");
    };
    if P2_FIRST_LBA > last_usable {
        fatal_msg("target cannot hold the p1+p2 layout");
    }
    let layout = [
        match Partition::new(TYPE_BIOS_GRUB, P1_UNIQUE_GUID, P1_FIRST_LBA, P1_LAST_LBA)
            .with_name(b"BIOSGRUB")
        {
            Ok(p) => p,
            Err(e) => fatal(e),
        },
        match Partition::new(TYPE_BASIC_DATA, P2_UNIQUE_GUID, P2_FIRST_LBA, last_usable)
            .with_name(b"REEMPLAZO")
        {
            Ok(p) => p,
            Err(e) => fatal(e),
        },
    ];
    let dev = GptDev(&target);
    if let Err(e) = gptwire::write(&dev, DISK_GUID, &layout) {
        fatal(e);
    }
    // Re-read through the adversarially-tested parser: `INST_OK`
    // asserts the *device's* state, not our intent.
    let gpt = match gptwire::read(&dev) {
        Ok(g) => g,
        Err(e) => fatal(e),
    };
    let p2 = gpt
        .partitions()
        .iter()
        .find(|p| p.type_guid == TYPE_BASIC_DATA)
        .copied();
    let Some(p2) = p2 else {
        fatal_msg("p2 missing from the freshly written GPT");
    };
    if p2.first_lba != P2_FIRST_LBA || p2.last_lba != last_usable {
        fatal_msg("p2 bounds on disk differ from the layout");
    }
    serial_println!(
        "install: GPT ok ({} partitions, p2 {}..{})",
        gpt.partitions().len(),
        p2.first_lba,
        p2.last_lba
    );

    // --- Step 2: format p2 as FAT16 (shared formatter) ---
    let part = p2_window(&target, p2.first_lba, p2.last_lba);
    let hidden = match u32::try_from(p2.first_lba) {
        Ok(h) => h,
        Err(_) => fatal_msg("p2 start does not fit the BPB hidden-sectors field"),
    };
    let geo = match fat::format_fat16(
        &part,
        &fat::FormatOpts {
            label: &VOLUME_LABEL,
            volume_id: VOLUME_ID,
            hidden_sectors: hidden,
        },
    ) {
        Ok(g) => g,
        Err(e) => fatal(e),
    };
    serial_println!(
        "install: FAT16 formatted ({} clusters x {} B)",
        geo.clusters,
        geo.sectors_per_cluster * 512
    );

    // --- Step 3: copy the payload from the source volume ---
    let src_disk = AtaDisk(source);
    let src_fs = match fat::Fat16::mount(&src_disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };
    let stamp = stamp();
    let mut readme = [0u8; PAYLOAD_CAP];
    let mut result = [0u8; PAYLOAD_CAP];
    let n_readme = match transfer(&src_fs, &part, PAYLOAD[0], &mut readme, stamp) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    let n_result = match transfer(&src_fs, &part, PAYLOAD[1], &mut result, stamp) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    serial_println!("install: copied {} files", PAYLOAD.len());

    // --- Step 4: re-mount p2 from scratch, read back byte-exact ---
    // Fresh `Part` + fresh `fat::Fat16`: no state from the writes
    // survives, so the read-back can only come from the device (the
    // FS2 proof shape, applied to the installed volume).
    let verify = p2_window(&target, p2.first_lba, p2.last_lba);
    let vfs = match fat::Fat16::mount(&verify) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };
    verify_file(&vfs, PAYLOAD[0], &readme[..n_readme]);
    verify_file(&vfs, PAYLOAD[1], &result[..n_result]);

    serial_println!("INST_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// Read `path` from `src` (bounded by the caller's buffer) and write
/// those exact bytes to a fresh mount of `dst` — one payload file's
/// copy. Returns the byte count (0 is a legal empty file).
fn transfer(
    src: &fat::Fat16<'_, AtaDisk<'_>>,
    dst_dev: &Part<'_>,
    path: &str,
    buf: &mut [u8],
    stamp: fat::Stamp,
) -> Result<usize, fat::Error> {
    let n = src.read_file(path, buf)?;
    let dst = fat::Fat16::mount(dst_dev)?;
    dst.write_file(path, &buf[..n], stamp)?;
    Ok(n)
}

/// Read `path` back from a fresh mount and require exactly
/// `expected` bytes — any mismatch is `FATAL: install:` + halt
/// (the `path` here is our own constant, safe to print; nothing
/// disk-sourced reaches the console).
fn verify_file(fs: &fat::Fat16<'_, Part<'_>>, path: &str, expected: &[u8]) {
    let mut buf = [0u8; PAYLOAD_CAP];
    let n = match fs.read_file(path, &mut buf) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    if n != expected.len() || buf[..n] != *expected {
        serial_println!(
            "FATAL: install: {} read back {} bytes, expected exactly {}",
            path,
            n,
            expected.len()
        );
        crate::halt();
    }
}

/// Fail-closed: name the refusal and stop the machine, so a broken
/// install can never look like a passing smoke.
fn fatal(e: impl core::fmt::Debug) -> ! {
    serial_println!("FATAL: install: {:?}", e);
    crate::halt()
}

/// Same, for preformatted messages (constants only — no disk data).
fn fatal_msg(msg: &str) -> ! {
    serial_println!("FATAL: install: {}", msg);
    crate::halt()
}
