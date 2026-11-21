//! PIO-mode ATA block driver for the legacy primary channel — the
//! installer's storage foundation (docs/installer.md, milestone `BLK_OK`).
//!
//! Scope and documented limits:
//!
//! - **PIO only, LBA28 only, reads only.** Sectors move as 16-bit
//!   words over the data port with `READ SECTORS` (0x20) in 28-bit LBA
//!   (≤ 128 GiB — the target's 120 GB disk fits). No LBA48, no
//!   `READ MULTIPLE`; `WRITE SECTORS` arrives with the GPT-writer
//!   milestone.
//! - **No ATAPI, no IRQ, no DMA.** A packet device (CD) answers
//!   IDENTIFY with ERR and is skipped; IRQ14 stays masked by the PIC,
//!   so every wait is a *bounded* poll ([`POLL_LIMIT`]) — polling is
//!   the whole protocol. Bus-master DMA (the PCI BM registers in BAR4)
//!   is future work: it needs PCI BAR setup and only pays off once
//!   throughput matters.
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

use crate::port::{inb, inw, outb};

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

/// Bounded poll budget (spins), mirroring `e1000`'s `TX_POLLS`: TCG
/// answers in microseconds, real silicon in milliseconds — the bound
/// turns a wedged drive into a failed probe instead of a hung boot.
/// A *missing* drive never spends it: status reads 00h/FFh and the
/// first iteration bails out.
const POLL_LIMIT: u32 = 10_000_000;

/// Magic pattern `xtask smoke-install` writes at LBA0 of `disk.img`.
/// Must stay byte-identical to `DISK_MAGIC` in `xtask/src/main.rs`.
const MAGIC: &[u8] = b"reemplazo-disk-v1";

/// One drive that answered `IDENTIFY` on the primary channel.
struct Drive {
    /// 0 = master, 1 = slave (drive-select bit in 0x1F6).
    unit: u8,
    /// Total addressable sectors, LBA28 (IDENTIFY words 60–61).
    sectors: u32,
    /// Model name (IDENTIFY words 27–46), ATA byte order decoded.
    model: [u8; 40],
}

impl Drive {
    /// Read `buf.len() / 512` sectors (1..=256) starting at `lba`
    /// into `buf`, which must hold a whole number of sectors.
    /// Returns `false` on any error or poll-timeout — never blocks
    /// forever.
    fn read_sectors(&self, lba: u32, buf: &mut [u8]) -> bool {
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
}

/// Probe the primary channel for a drive whose LBA0 starts with the
/// installer's [`MAGIC`]; on success print the drive line and `BLK_OK`
/// (machine-checked by `cargo xtask smoke-install`).
///
/// Prints **nothing** when no drive answers or the magic is absent:
/// the main boot smoke has no disk, and its marker chain must stay
/// untouched (AGENTS.md).
pub fn probe() {
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
            return;
        }
    }
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

/// Checksum byte that follows the magic: wrapping sum of its bytes.
/// Duplicated in xtask (host crates cannot depend on the kernel).
fn magic_checksum() -> u8 {
    MAGIC.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// LBA0 must start with [`MAGIC`] followed by its checksum byte.
fn has_magic(sector: &[u8; 512]) -> bool {
    sector.starts_with(MAGIC) && sector[MAGIC.len()] == magic_checksum()
}
