//! PIO-mode ATA block driver for the legacy primary channel — the
//! installer's storage foundation (docs/installer.md, milestone `BLK_OK`).
//!
//! Scope and documented limits:
//!
//! - **PIO only, LBA28 only, reads and writes.** Sectors move as 16-bit
//!   words over the data port with `READ SECTORS` (0x20) and
//!   `WRITE SECTORS` (0x30) in 28-bit LBA (≤ 128 GiB — the target's
//!   120 GB disk fits). No LBA48, no `READ MULTIPLE`/`WRITE MULTIPLE`.
//!   The write path (FS2, `FS_WRITE_OK`) is the same discipline as the
//!   reads: bounded polls, fail-closed, and a capacity check against the
//!   IDENTIFY-reported sector count before any port is programmed.
//! - **No ATAPI, no IRQ, no DMA.** A packet device (CD) answers
//!   IDENTIFY with ERR and is skipped; IRQ14 stays masked by the PIC,
//!   so every wait is a *bounded* poll ([`POLL_LIMIT`]) — polling is
//!   the whole protocol. Bus-master DMA (the PCI BM registers in BAR4)
//!   is future work: it needs PCI BAR setup and only pays off once
//!   throughput matters; the ATA `FLUSH CACHE` (0xE7) command for
//!   drive-write-cache ordering is likewise future work (documented in
//!   `fat::write`: crash consistency is not an FS2 goal).
//! - **Legacy fixed ports, no PCI BAR decoding.** The command block
//!   lives at 0x1F0–0x1F7 and the control block at 0x3F6 —
//!   ISA-compatible fixed addresses that any PC chipset's IDE
//!   compatibility interface decodes unconditionally (QEMU's PIIX3
//!   IDE, what `-drive …,if=ide` attaches to, registers them at
//!   realize time with no guest PCI setup), so this driver needs no
//!   PCI probe and no BAR mapping. (The MacBook's ICH7 runs its disk
//!   in **AHCI** mode, where these ports are not the path — real
//!   hardware gets the separate AHCI milestone; this driver is the
//!   QEMU/installer path.)
//!
//! Why it is the installer's foundation: GPT, FAT32 and the payload
//! layout are all sector I/O on the target disk, so every installer
//! milestone stacks on this layer. It also runs on *every* boot —
//! including the main smoke, which has no disk — so a missing drive
//! must answer `None` in a couple of port reads (QEMU's empty channel
//! reads status 00h, a floating bus reads FFh) and never hang boot;
//! that is the same bounded-poll discipline as `crate::rtc`.

use crate::port::{inb, inw, outb, outw};

// --- Primary channel ports (legacy fixed addresses, see module docs) ---
const DATA: u16 = 0x1F0; // 16-bit PIO data port
const SECTOR_COUNT: u16 = 0x1F2;
const LBA_LOW: u16 = 0x1F3; // LBA bits 0..7
const LBA_MID: u16 = 0x1F4; // LBA bits 8..15
const LBA_HIGH: u16 = 0x1F5; // LBA bits 16..23
const DRIVE_HEAD: u16 = 0x1F6; // drive select + LBA bits 24..27
const STATUS: u16 = 0x1F7; // read
const COMMAND: u16 = 0x1F7; // write
const ALT_STATUS: u16 = 0x3F6; // read: alternate status (no INTRQ side effect)

// --- Status register bits (ATA-1) ---------------------------------------
const ST_ERR: u8 = 0x01; // error / command aborted (ATAPI IDENTIFY lands here)
const ST_DRQ: u8 = 0x08; // data ready for the host
const ST_BSY: u8 = 0x80; // command in progress

// --- Commands ------------------------------------------------------------
const CMD_IDENTIFY: u8 = 0xEC;
const CMD_READ_SECTORS: u8 = 0x20;
const CMD_WRITE_SECTORS: u8 = 0x30;

/// Bounded poll budget (spins), mirroring `e1000`'s `TX_POLLS`: TCG
/// answers in microseconds, real silicon in milliseconds — the bound
/// turns a wedged drive into a failed probe instead of a hung boot.
/// A *missing* drive never spends it: status reads 00h/FFh and the
/// first iteration bails out.
const POLL_LIMIT: u32 = 10_000_000;

/// Magic pattern `xtask smoke-install` writes at LBA0 of `disk.img`.
/// Must stay byte-identical to `DISK_MAGIC` in `xtask/src/main.rs`.
const MAGIC: &[u8] = b"reemplazo-disk-v1";

/// Byte offset of [`MAGIC`] inside LBA0 — the FAT boot sector's
/// **bootstrap area** (62..510, the region after the BPB that FAT never
/// parses). Must stay byte-identical to `DISK_MAGIC_OFFSET` in xtask.
///
/// Why the probe no longer starts at offset 0: since FS1, LBA0 is a real
/// FAT boot sector — bytes 0..2 are the jump instruction, 3..10 the OEM
/// name and 11..62 the BPB, and an arbitrary string there would break
/// the FAT spec (our own reader refuses a boot sector without a valid
/// jump and a well-formed BPB). The signature `55 AA` still closes the
/// sector at 510..512. Relocating the magic keeps probe's semantics
/// *identical* — same 17 bytes, same wrapping-sum checksum byte right
/// after them — only the documented offset moved, and both sides of the
/// contract live in this repo.
const MAGIC_OFFSET: usize = 62;

/// One drive that answered `IDENTIFY` on the primary channel.
/// `pub(crate)` so `crate::fs` can mount a filesystem over its reads.
pub(crate) struct Drive {
    /// 0 = master, 1 = slave (drive-select bit in 0x1F6).
    unit: u8,
    /// Total addressable sectors, LBA28 (IDENTIFY words 60–61) — the
    /// capacity the filesystem layer bounds every read *and write*
    /// against (FS2 refuses writes past it, see [`write_sectors`]).
    pub(crate) sectors: u32,
    /// Model name (IDENTIFY words 27–46), ATA byte order decoded.
    model: [u8; 40],
}

impl Drive {
    /// Read `buf.len() / 512` sectors (1..=256) starting at `lba`
    /// into `buf`, which must hold a whole number of sectors.
    /// Returns `false` on any error or poll-timeout — never blocks
    /// forever.
    pub(crate) fn read_sectors(&self, lba: u32, buf: &mut [u8]) -> bool {
        let count = buf.len() / 512;
        if buf.is_empty() || !buf.len().is_multiple_of(512) || count > 256 {
            return false;
        }
        // End of the request must stay inside both the drive's reported
        // capacity and the LBA28 window (bits 0..27 — that's all the
        // drive/head register can carry).
        let end = u64::from(lba) + count as u64;
        if end > u64::from(self.sectors) || end > 1 << 28 {
            return false;
        }

        // SAFETY: fixed primary-channel ports (module docs); register
        // widths match the ATA contract; single-core boot, IRQ14 masked.
        unsafe {
            // Select the unit first so the LBA registers below land on
            // it, then the ≥400 ns settle time via alternate-status
            // reads (0x3F6 reads have no INTRQ side effect).
            outb(
                DRIVE_HEAD,
                0xE0 | (self.unit << 4) | (((lba >> 24) as u8) & 0x0F),
            );
            for _ in 0..4 {
                let _ = inb(ALT_STATUS);
            }
            if !wait_bsy_clear() {
                return false;
            }
            outb(SECTOR_COUNT, count as u8); // 256 sectors encodes as 0
            outb(LBA_LOW, lba as u8);
            outb(LBA_MID, (lba >> 8) as u8);
            outb(LBA_HIGH, (lba >> 16) as u8);
            outb(COMMAND, CMD_READ_SECTORS);

            // Whole sectors only (checked above), so the tail is empty.
            let (sectors, _) = buf.as_chunks_mut::<512>();
            for sector in sectors {
                if !wait_drq() {
                    return false;
                }
                let (pairs, _) = sector.as_chunks_mut::<2>();
                for pair in pairs {
                    let word = inw(DATA);
                    // ATA hands byte 0 of the sector in the low half
                    // of the word (QEMU: cpu_to_le16 of the buffer).
                    pair[0] = word as u8;
                    pair[1] = (word >> 8) as u8;
                }
            }
            // ERR after the last word means the tail end failed.
            inb(STATUS) & ST_ERR == 0
        }
    }

    /// Write `buf.len() / 512` sectors (1..=256) from `buf` starting at
    /// `lba`, which must hold a whole number of sectors. Returns `false`
    /// on any error, capacity violation or poll-timeout — never blocks
    /// forever, never writes a byte outside the IDENTIFY-reported
    /// capacity (FS2's device-side bound, mirrored from the read path).
    ///
    /// Protocol (PIO `WRITE SECTORS`, 0x30, no IRQ — polling only):
    /// program the LBA/sector-count registers, issue the command, then
    /// for each sector wait (bounded) for DRQ, push 256 words, and wait
    /// (bounded) for the drive to consume the sector before the next
    /// one — the final wait doubles as the command-completion check
    /// (BSY clear, DRQ clear, no ERR). Drive-side write caches are not
    /// flushed (`FLUSH CACHE` is future work — see `fat::write`'s
    /// crash-consistency note).
    pub(crate) fn write_sectors(&self, lba: u32, buf: &[u8]) -> bool {
        let count = buf.len() / 512;
        if buf.is_empty() || !buf.len().is_multiple_of(512) || count > 256 {
            return false;
        }
        // End of the request must stay inside both the drive's reported
        // capacity and the LBA28 window (bits 0..27 — that's all the
        // drive/head register can carry).
        let end = u64::from(lba) + count as u64;
        if end > u64::from(self.sectors) || end > 1 << 28 {
            return false;
        }

        // SAFETY: fixed primary-channel ports (module docs); register
        // widths match the ATA contract; single-core boot, IRQ14 masked
        // (polling only — no DMA, no IRQ on this path either).
        unsafe {
            // Select the unit first so the LBA registers below land on
            // it, then the ≥400 ns settle time via alternate-status
            // reads (0x3F6 reads have no INTRQ side effect).
            outb(
                DRIVE_HEAD,
                0xE0 | (self.unit << 4) | (((lba >> 24) as u8) & 0x0F),
            );
            for _ in 0..4 {
                let _ = inb(ALT_STATUS);
            }
            if !wait_bsy_clear() {
                return false;
            }
            outb(SECTOR_COUNT, count as u8); // 256 sectors encodes as 0
            outb(LBA_LOW, lba as u8);
            outb(LBA_MID, (lba >> 8) as u8);
            outb(LBA_HIGH, (lba >> 16) as u8);
            outb(COMMAND, CMD_WRITE_SECTORS);

            // Whole sectors only (checked above), so the tail is empty.
            let (sectors, _) = buf.as_chunks::<512>();
            for sector in sectors {
                if !wait_drq() {
                    return false;
                }
                let (pairs, _) = sector.as_chunks::<2>();
                for pair in pairs {
                    // ATA wants byte 0 of the sector in the low half of
                    // the word — the inverse of the read path's `inw`.
                    let word = u16::from_le_bytes([pair[0], pair[1]]);
                    outw(DATA, word);
                }
                // The drive clears DRQ once it has consumed the 256
                // words; wait for that before offering the next sector,
                // and (for the last one) for BSY to drop with no ERR —
                // the bounded command-completion check.
                if !wait_drq_clear() {
                    return false;
                }
            }
            true
        }
    }
}

/// Probe the primary channel for a drive whose LBA0 starts with the
/// installer's [`MAGIC`] (at [`MAGIC_OFFSET`]); on success print the
/// drive line and `BLK_OK` (machine-checked by `cargo xtask
/// smoke-install`) and hand the drive back for `crate::fs::prove`.
///
/// Prints **nothing** and returns `None` when no drive answers or the
/// magic is absent: the main boot smoke has no disk, and its marker
/// chain must stay untouched (AGENTS.md).
pub(crate) fn probe() -> Option<Drive> {
    for unit in [0u8, 1] {
        let Some(drive) = identify(unit) else {
            continue;
        };
        let mut sector = [0u8; 512];
        if drive.read_sectors(0, &mut sector) && has_magic(&sector) {
            // ATA pads model strings with spaces; keep the serial line
            // printable even if a device reports garbage bytes.
            let end = drive
                .model
                .iter()
                .rposition(|&b| b != b' ')
                .map_or(0, |i| i + 1);
            let name = core::str::from_utf8(&drive.model[..end]).unwrap_or("<non-ascii>");
            let unit_name = if drive.unit == 0 { "master" } else { "slave" };
            let sectors = drive.sectors;
            serial_println!(
                "ata: {unit_name} '{name}' {sectors} sectors ({} MiB)",
                sectors / 2048
            );
            serial_println!("BLK_OK"); // machine-checked by `cargo xtask smoke-install`
            return Some(drive);
        }
    }
    None
}

/// `IDENTIFY DEVICE` on `unit` (0 = master, 1 = slave); `None` when no
/// drive answers, the device is not an ATA disk (ATAPI answers with
/// ERR), or the identify data is implausible.
fn identify(unit: u8) -> Option<Drive> {
    // SAFETY: fixed primary-channel ports (module docs); byte-wide
    // access matches the register contract; single-core boot, IRQ14
    // masked (polling only). Returns the raw IDENTIFY words.
    let id = unsafe {
        // Select the unit (0xE0 = LBA mode + drive select), then let
        // the ≥400 ns settle time pass with four alternate-status
        // reads (0x3F6 reads have no INTRQ side effect).
        outb(DRIVE_HEAD, 0xE0 | (unit << 4));
        for _ in 0..4 {
            let _ = inb(ALT_STATUS);
        }
        if !wait_bsy_clear() {
            return None; // empty unit: status 00h/FFh → immediate None
        }
        outb(COMMAND, CMD_IDENTIFY);
        if !wait_drq() {
            return None; // ATAPI (ERR) or wedged/absent
        }

        let mut id = [0u16; 256];
        for word in &mut id {
            *word = inw(DATA);
        }
        if inb(STATUS) & ST_ERR != 0 {
            return None; // transfer failed mid-way
        }
        id
    };

    // Word 0 bit 15 set = packet device; it should already have
    // failed with ERR, but don't trust a misbehaving device.
    if id[0] & 0x8000 != 0 {
        return None;
    }

    // Words 60–61: total LBA28 addressable sectors (QEMU fills
    // these, capped at 2^28-1). Zero = no LBA28 capacity = unusable.
    let sectors = u32::from(id[60]) | (u32::from(id[61]) << 16);
    if sectors == 0 {
        return None;
    }

    // Words 27–46: model, 40 ASCII bytes stored byte-swapped per
    // word (ATA string convention — first char in the high byte).
    let mut model = [0u8; 40];
    for (i, &word) in id[27..47].iter().enumerate() {
        model[2 * i] = (word >> 8) as u8;
        model[2 * i + 1] = (word & 0xFF) as u8;
    }

    Some(Drive {
        unit,
        sectors,
        model,
    })
}

/// Bounded wait for BSY to clear (drive ready to accept a command).
/// `false` when status reads 00h/FFh — nothing answers on this unit —
/// or the budget runs out.
fn wait_bsy_clear() -> bool {
    let mut spins = 0u32;
    loop {
        // SAFETY: primary-channel status port; read-only, fixed address.
        let status = unsafe { inb(STATUS) };
        if status == 0x00 || status == 0xFF {
            return false;
        }
        if status & ST_BSY == 0 {
            return true;
        }
        spins += 1;
        if spins > POLL_LIMIT {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Bounded wait for DRQ (data ready) after a command: succeeds once
/// BSY has cleared with DRQ set; fails on ERR (command error, ATAPI
/// IDENTIFY), a vanished drive (00h/FFh), or budget exhaustion.
fn wait_drq() -> bool {
    let mut spins = 0u32;
    loop {
        // SAFETY: primary-channel status port; read-only, fixed address.
        let status = unsafe { inb(STATUS) };
        if status == 0x00 || status == 0xFF {
            return false;
        }
        if status & ST_BSY == 0 {
            if status & ST_ERR != 0 {
                return false;
            }
            if status & ST_DRQ != 0 {
                return true;
            }
            // BSY clear, no ERR, no DRQ: transient — keep polling
            // within the budget.
        }
        spins += 1;
        if spins > POLL_LIMIT {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Bounded wait for the drive to *finish* a data phase: BSY clear and
/// DRQ clear (the drive consumed the 256 words), no ERR. Fails on a
/// vanished drive (00h/FFh) or budget exhaustion — the write path's
/// per-sector handshake and its final command-completion check.
fn wait_drq_clear() -> bool {
    let mut spins = 0u32;
    loop {
        // SAFETY: primary-channel status port; read-only, fixed address.
        let status = unsafe { inb(STATUS) };
        if status == 0x00 || status == 0xFF {
            return false;
        }
        if status & ST_BSY == 0 && status & ST_DRQ == 0 {
            return status & ST_ERR == 0;
        }
        spins += 1;
        if spins > POLL_LIMIT {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// Checksum byte that follows the magic: wrapping sum of its bytes.
/// Duplicated in xtask (host crates cannot depend on the kernel).
fn magic_checksum() -> u8 {
    MAGIC.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// LBA0 must carry [`MAGIC`] at [`MAGIC_OFFSET`] followed by its
/// checksum byte. Slice access only (never raw indexing): the offset is
/// a constant, but the bytes are disk data.
fn has_magic(sector: &[u8; 512]) -> bool {
    let end = MAGIC_OFFSET + MAGIC.len();
    sector.get(MAGIC_OFFSET..end) == Some(MAGIC) && sector.get(end) == Some(&magic_checksum())
}
