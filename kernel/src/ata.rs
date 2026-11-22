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
//!   in **AHCI** mode, where these ports are not the path — the SATA
//!   driver is `crate::ahci` [milestone `AHCI_OK`], the other variant
//!   of the [`Disk`] block enum below; this IDE driver stays the
//!   QEMU/installer path and the byte-identical baseline.)
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

/// Magic pattern `xtask smoke-install` writes at LBA0 of the *target*
/// image (`target.img`, the blank disk the installer may wipe) — a
/// different string on purpose, so the source and target can never be
/// confused. Must stay byte-identical to `TARGET_DISK_MAGIC` in
/// `xtask/src/main.rs`.
///
/// Safety rule this encodes: the installer only ever formats a disk
/// that carries this marker (fail-closed — an unmarked second disk is
/// ignored, never wiped). Real-hardware installs with an unmarked disk
/// go through the guided `install <id>` shell builtin instead
/// (docs/installer.md §7.1, future milestone).
const TARGET_MAGIC: &[u8] = b"reemplazo-target-v1";

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
    /// Which unit on the channel this drive answers on (0 = master,
    /// 1 = slave) — `crate::install` uses it to skip the *source*
    /// disk when hunting for the target.
    pub(crate) fn unit(&self) -> u8 {
        self.unit
    }

    /// The IDENTIFY model string, sanitized for printing: trailing
    /// spaces trimmed, every byte outside printable ASCII replaced
    /// with `?` — the bytes come from the device itself, so they are
    /// untrusted and must not reach the console raw (the
    /// "sanitize before `serial_println!`" rule; the macro also
    /// evaluates its arguments twice, hence writing into a
    /// caller-provided buffer once instead of formatting per call).
    /// All output bytes are ASCII by construction, so the `&str`
    /// conversion cannot fail (`unwrap_or` keeps that honest without
    /// a panic path).
    pub(crate) fn model_name<'a>(&self, out: &'a mut [u8; 40]) -> &'a str {
        let end = self
            .model
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |i| i + 1);
        for (dst, &src) in out.iter_mut().take(end).zip(&self.model[..end]) {
            *dst = if src.is_ascii_graphic() || src == b' ' {
                src
            } else {
                b'?'
            };
        }
        core::str::from_utf8(&out[..end]).unwrap_or("?")
    }

    /// Read `buf.len() / 512` sectors (1..=256) starting at `lba`
    /// into `buf`, which must hold a whole number of sectors.
    /// Returns `false` on any error or poll-timeout — never blocks
    /// forever.
    ///
    /// **One `READ SECTORS` command per sector** (not one command for
    /// the whole request): every command here is the exact
    /// single-sector sequence the boot proofs exercise end to end, so
    /// no multi-sector data-phase handshake (DRQ clear → re-assert
    /// between sectors) is ever *assumed*. The per-command overhead is
    /// ~10 port accesses per 512 bytes — noise next to the 256 word
    /// transfers themselves.
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

        for i in 0..count {
            // `end` above bounds `lba + i` inside the LBA28 window.
            let sector_lba = lba + i as u32;
            let sector = match buf.get_mut(i * 512..i * 512 + 512) {
                Some(s) => s,
                None => return false, // unreachable (count derived from len)
            };
            // SAFETY: fixed primary-channel ports (module docs); register
            // widths match the ATA contract; single-core boot, IRQ14 masked.
            unsafe {
                // Select the unit first so the LBA registers below land on
                // it, then the ≥400 ns settle time via alternate-status
                // reads (0x3F6 reads have no INTRQ side effect).
                outb(
                    DRIVE_HEAD,
                    0xE0 | (self.unit << 4) | (((sector_lba >> 24) as u8) & 0x0F),
                );
                for _ in 0..4 {
                    let _ = inb(ALT_STATUS);
                }
                if !wait_bsy_clear() {
                    return false;
                }
                outb(SECTOR_COUNT, 1);
                outb(LBA_LOW, sector_lba as u8);
                outb(LBA_MID, (sector_lba >> 8) as u8);
                outb(LBA_HIGH, (sector_lba >> 16) as u8);
                outb(COMMAND, CMD_READ_SECTORS);

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
                // ERR after the last word means the transfer failed.
                if inb(STATUS) & ST_ERR != 0 {
                    return false;
                }
            }
        }
        true
    }

    /// Write `buf.len() / 512` sectors (1..=256) from `buf` starting at
    /// `lba`, which must hold a whole number of sectors. Returns `false`
    /// on any error, capacity violation or poll-timeout — never blocks
    /// forever, never writes a byte outside the IDENTIFY-reported
    /// capacity (FS2's device-side bound, mirrored from the read path).
    ///
    /// Protocol (PIO `WRITE SECTORS`, 0x30, no IRQ — polling only):
    /// **one command per sector**, each the exact single-sector
    /// sequence FS2 proved end to end — select + ≥400 ns settle, bounded
    /// BSY wait, program LBA/count, issue, bounded DRQ wait, push 256
    /// words, bounded completion wait (BSY clear, DRQ clear, no ERR).
    ///
    /// Why not one command for the whole request (the I1 milestone hit
    /// this the hard way): between data phases of a *multi-sector*
    /// command the drive re-asserts DRQ for the next sector, so a
    /// "wait for DRQ to go low" completion poll can miss the low window
    /// entirely and spin to its budget — QEMU does exactly this. One
    /// command per sector means the completion wait only ever runs
    /// where it is proven: the command's final (only) sector. Cost:
    /// ~10 extra port accesses per 512 bytes, next to the 256 words
    /// the data phase moves anyway. Drive-side write caches are not
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

        for i in 0..count {
            // `end` above bounds `lba + i` inside the LBA28 window.
            let sector_lba = lba + i as u32;
            let sector = match buf.get(i * 512..i * 512 + 512) {
                Some(s) => s,
                None => return false, // unreachable (count derived from len)
            };
            // SAFETY: fixed primary-channel ports (module docs); register
            // widths match the ATA contract; single-core boot, IRQ14 masked
            // (polling only — no DMA, no IRQ on this path either).
            unsafe {
                // Select the unit first so the LBA registers below land on
                // it, then the ≥400 ns settle time via alternate-status
                // reads (0x3F6 reads have no INTRQ side effect).
                outb(
                    DRIVE_HEAD,
                    0xE0 | (self.unit << 4) | (((sector_lba >> 24) as u8) & 0x0F),
                );
                for _ in 0..4 {
                    let _ = inb(ALT_STATUS);
                }
                if !wait_bsy_clear() {
                    return false;
                }
                outb(SECTOR_COUNT, 1);
                outb(LBA_LOW, sector_lba as u8);
                outb(LBA_MID, (sector_lba >> 8) as u8);
                outb(LBA_HIGH, (sector_lba >> 16) as u8);
                outb(COMMAND, CMD_WRITE_SECTORS);

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
                // words; with no further sectors in this command that
                // is the bounded command-completion check (BSY drop,
                // DRQ drop, no ERR).
                if !wait_drq_clear() {
                    return false;
                }
            }
        }
        true
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
            let mut name_buf = [0u8; 40];
            let name = drive.model_name(&mut name_buf);
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

/// Find the installer's *target* disk: the unit on the primary
/// channel that is **not** `source_unit` and whose LBA0 carries
/// [`TARGET_MAGIC`]. Prints **nothing** and returns `None` when no
/// such disk exists — the diskless/single-disk neutrality every boot
/// proof depends on (the main smoke has no disks at all; the FS1/FS2
/// smoke has only the source). An unmarked second disk is *also* a
/// silent `None`: the installer never wipes a disk it was not handed
/// the target marker for (module docs of `crate::install`).
pub(crate) fn probe_target(source_unit: u8) -> Option<Drive> {
    for unit in [0u8, 1] {
        if unit == source_unit {
            continue;
        }
        let Some(drive) = identify(unit) else {
            continue;
        };
        let mut sector = [0u8; 512];
        if drive.read_sectors(0, &mut sector) && has_target_magic(&sector) {
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
pub(crate) fn has_magic(sector: &[u8; 512]) -> bool {
    let end = MAGIC_OFFSET + MAGIC.len();
    sector.get(MAGIC_OFFSET..end) == Some(MAGIC) && sector.get(end) == Some(&magic_checksum())
}

/// Same shape as [`has_magic`] for [`TARGET_MAGIC`] (its own wrapping
/// sum — the marker identifies the wipe-able target disk, so it gets
/// its own checksum byte and its own string).
pub(crate) fn has_target_magic(sector: &[u8; 512]) -> bool {
    let end = MAGIC_OFFSET + TARGET_MAGIC.len();
    sector.get(MAGIC_OFFSET..end) == Some(TARGET_MAGIC)
        && sector.get(end) == Some(&target_magic_checksum())
}

/// Wrapping-sum checksum byte that follows [`TARGET_MAGIC`] —
/// duplicated in xtask's `write_target_image`.
fn target_magic_checksum() -> u8 {
    TARGET_MAGIC.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

// ---------------------------------------------------------------------------
// The block-device abstraction both drivers sit behind
// ---------------------------------------------------------------------------

/// A block disk the filesystem, GPT and installer work on — **either**
/// the legacy-IDE [`Drive`] or an [`crate::ahci::AhciDisk`].
///
/// Why an enum and not a trait (the same call `netstack::Nic` made for
/// e1000/sky2): there are exactly two implementations, the method
/// surface is four methods, and an enum keeps the call sites free of
/// `dyn` dispatch and of a `&mut self` requirement — both drivers are
/// stateless from the caller's point of view (`read_sectors`/`write_*`
/// take `&self`), which is what lets `fat::BlockDevice`'s shared
/// adapter and `gptwire::Device` keep their `&self` signatures
/// unchanged.
///
/// Semantics are the IDE driver's documented contract, unchanged:
/// whole 512-byte sectors only, 1..=256 sectors per call, every range
/// checked against the IDENTIFY-reported capacity inside the driver,
/// and `false` (never a panic, never a hang) on any failure. The AHCI
/// side splits a 256-sector request into two 128-sector commands
/// internally; the caller cannot tell, and neither can the smoke.
pub(crate) enum Disk {
    /// Legacy IDE primary-channel drive (QEMU's disk path, unit 0/1).
    Ide(Drive),
    /// AHCI/SATA disk on one port (the MacBook's ICH7 path). Boxed so
    /// the enum stays pointer-sized: the AHCI struct carries its DMA
    /// frame handles and a 40-byte model string, and the IDE path (the
    /// smoke's hot path) should not pay for that.
    Ahci(alloc::boxed::Box<crate::ahci::AhciDisk>),
}

impl Disk {
    /// Wrap a probed AHCI disk in the shared block layer.
    pub(crate) fn ahci(disk: crate::ahci::AhciDisk) -> Disk {
        Disk::Ahci(alloc::boxed::Box::new(disk))
    }

    /// Total addressable 512-byte sectors (IDENTIFY on either driver).
    pub(crate) fn sectors(&self) -> u32 {
        match self {
            Disk::Ide(drive) => drive.sectors,
            Disk::Ahci(disk) => disk.sectors(),
        }
    }

    /// Read whole sectors into `buf` (see the type docs for the
    /// contract). `false` on any driver-level failure.
    pub(crate) fn read_sectors(&self, lba: u32, buf: &mut [u8]) -> bool {
        match self {
            Disk::Ide(drive) => drive.read_sectors(lba, buf),
            Disk::Ahci(disk) => disk.read_sectors(lba, buf),
        }
    }

    /// Write whole sectors from `buf`; same contract as the read path.
    pub(crate) fn write_sectors(&self, lba: u32, buf: &[u8]) -> bool {
        match self {
            Disk::Ide(drive) => drive.write_sectors(lba, buf),
            Disk::Ahci(disk) => disk.write_sectors(lba, buf),
        }
    }

    /// Sanitized model string (see [`Drive::model_name`]; the AHCI
    /// driver uses the identical sanitization).
    pub(crate) fn model_name<'a>(&self, out: &'a mut [u8; 40]) -> &'a str {
        match self {
            Disk::Ide(drive) => drive.model_name(out),
            Disk::Ahci(disk) => disk.model_name(out),
        }
    }

    /// Which transport this disk came through — log lines only.
    pub(crate) fn transport(&self) -> &'static str {
        match self {
            Disk::Ide(_) => "ide",
            Disk::Ahci(_) => "ahci",
        }
    }

    /// The legacy-IDE drive behind this disk, if any. The S5 key-file
    /// reader and G3's checkout adapter still take `&Drive` (their
    /// modules are IDE-only by design: `smoke-ssh` attaches IDE disks
    /// and the checkout proof is the IDE path's), so a source disk that
    /// came through AHCI simply has no key file and no extra checkout.
    pub(crate) fn ide(&self) -> Option<&Drive> {
        match self {
            Disk::Ide(drive) => Some(drive),
            Disk::Ahci(_) => None,
        }
    }
}
