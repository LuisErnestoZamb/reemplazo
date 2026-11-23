//! Minimal PIO/LBA28 driver for a SATA controller in **IDE mode**
//! (ICH7 `-M`, the real MacBook's `8086:27c4` at 00:1f.2).
//!
//! The legacy driver in `ata.rs` hardcodes the ISA-compatible primary
//! channel (0x1F0/0x3F6). Linux reports this machine's disk on a PCI
//! *native-mode IDE* channel instead:
//!
//! ```text
//! 00:1f.2 IDE interface [0101] 8086:27c4 (rev 02)
//!   Region 0: I/O ports at 20c8   <- command block (DATA..COMMAND)
//!   Region 1: I/O ports at 20ec   <- control block (ALT_STATUS)
//!   driver: ata_piix, MAP [ P0 P2 -- -- ]
//! ```
//!
//! This module is deliberately small and read/write only: it exists so
//! the bring-up log can see a disk that the AHCI and legacy-IDE probes
//! both miss. It uses the exact single-sector bounded-poll discipline
//! as `ata.rs` (one command per 512 bytes, no DMA, no IRQ, no
//! multi-sector handshake assumption). It does **not** change the
//! installer source/target selection, so every QEMU smoke stays
//! byte-identical.
//!
//! LBA28 suffices: the log region on the 120 GB disk starts at LBA
//! 234440708, below the 2^28 = 268435456 ceiling.

use crate::pci::Scan;
use crate::port::{inb, inw, outb, outw};

const POLL_LIMIT: u32 = 10_000_000;
const ST_ERR: u8 = 0x01;
const ST_DRQ: u8 = 0x08;
const ST_BSY: u8 = 0x80;
const CMD_IDENTIFY: u8 = 0xEC;
const CMD_READ: u8 = 0x20;
const CMD_WRITE: u8 = 0x30;

const ICH7_SATA_IDE: (u16, u16) = (0x8086, 0x27C4);

/// Boot-time snapshot for the SSH `logstatus` diagnostic: 0 = no
/// matching PCI function, 1 = BARs not I/O, 2 = IDENTIFY failed,
/// 3 = zero capacity, 4 = bound successfully.
pub(crate) fn diagnostics() -> (u8, u32, u32, u32) {
    // SAFETY: single-core boot; written only by `probe` at boot.
    unsafe {
        let d = core::ptr::addr_of!(DIAG).read();
        (d.state, d.bar0, d.bar1, d.sectors)
    }
}

struct Diag {
    state: u8,
    bar0: u32,
    bar1: u32,
    sectors: u32,
}

static mut DIAG: Diag = Diag {
    state: 0,
    bar0: 0,
    bar1: 0,
    sectors: 0,
};

fn mark(state: u8, bar0: u32, bar1: u32, sectors: u32) {
    // SAFETY: see `diagnostics`.
    unsafe {
        core::ptr::addr_of_mut!(DIAG).write(Diag {
            state,
            bar0,
            bar1,
            sectors,
        });
    }
}

/// One PCI-native IDE channel. `cmd` is the command-block base (BAR0);
/// `ctl` is the separate control-block base (BAR1), not `cmd + 6`.
#[derive(Clone, Copy)]
pub(crate) struct PciIde {
    cmd: u16,
    ctl: u16,
    pub(crate) sectors: u32,
}

impl PciIde {
    pub(crate) const ZERO: Self = Self {
        cmd: 0,
        ctl: 0,
        sectors: 0,
    };

    fn data(&self) -> u16 {
        self.cmd
    }
    fn count(&self) -> u16 {
        self.cmd + 2
    }
    fn lba_low(&self) -> u16 {
        self.cmd + 3
    }
    fn lba_mid(&self) -> u16 {
        self.cmd + 4
    }
    fn lba_high(&self) -> u16 {
        self.cmd + 5
    }
    fn drive_head(&self) -> u16 {
        self.cmd + 6
    }
    fn status(&self) -> u16 {
        self.cmd + 7
    }
    fn command(&self) -> u16 {
        self.cmd + 7
    }
    fn alt_status(&self) -> u16 {
        self.ctl
    }

    fn wait_bsy_clear(&self) -> bool {
        let mut spins = 0u32;
        loop {
            // SAFETY: PCI BAR I/O port, read-only; single-core boot.
            let status = unsafe { inb(self.status()) };
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

    fn wait_drq(&self) -> bool {
        let mut spins = 0u32;
        loop {
            // SAFETY: see `wait_bsy_clear`.
            let status = unsafe { inb(self.status()) };
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
            }
            spins += 1;
            if spins > POLL_LIMIT {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    fn wait_drq_clear(&self) -> bool {
        let mut spins = 0u32;
        loop {
            // SAFETY: see `wait_bsy_clear`.
            let status = unsafe { inb(self.status()) };
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

    fn select(&self, unit: u8, lba: u32) {
        // SAFETY: PCI BAR I/O ports; drive select then four alternate
        // status reads give the required >=400 ns settle time.
        unsafe {
            outb(
                self.drive_head(),
                0xE0 | (unit << 4) | (((lba >> 24) as u8) & 0x0F),
            );
            for _ in 0..4 {
                let _ = inb(self.alt_status());
            }
        }
    }

    /// Read one or more 512-byte sectors. Exactly one command per sector.
    pub(crate) fn read_sectors(&self, lba: u32, buf: &mut [u8]) -> bool {
        let count = buf.len() / 512;
        if self.sectors == 0
            || buf.is_empty()
            || !buf.len().is_multiple_of(512)
            || u64::from(lba) + count as u64 > u64::from(self.sectors)
        {
            return false;
        }
        for i in 0..count {
            let sector_lba = lba + i as u32;
            let Some(sector) = buf.get_mut(i * 512..i * 512 + 512) else {
                return false;
            };
            self.select(0, sector_lba);
            if !self.wait_bsy_clear() {
                return false;
            }
            // SAFETY: register widths match ATA; bounded polls; no IRQ.
            unsafe {
                outb(self.count(), 1);
                outb(self.lba_low(), sector_lba as u8);
                outb(self.lba_mid(), (sector_lba >> 8) as u8);
                outb(self.lba_high(), (sector_lba >> 16) as u8);
                outb(self.command(), CMD_READ);
                if !self.wait_drq() {
                    return false;
                }
                let (pairs, _) = sector.as_chunks_mut::<2>();
                for pair in pairs {
                    let word = inw(self.data());
                    pair[0] = word as u8;
                    pair[1] = (word >> 8) as u8;
                }
            }
        }
        true
    }

    /// Write one or more sectors, with the same one-command-per-sector
    /// and bounded-poll discipline as the legacy driver.
    pub(crate) fn write_sectors(&self, lba: u32, buf: &[u8]) -> bool {
        let count = buf.len() / 512;
        if self.sectors == 0
            || buf.is_empty()
            || !buf.len().is_multiple_of(512)
            || u64::from(lba) + count as u64 > u64::from(self.sectors)
        {
            return false;
        }
        for i in 0..count {
            let sector_lba = lba + i as u32;
            let Some(sector) = buf.get(i * 512..i * 512 + 512) else {
                return false;
            };
            self.select(0, sector_lba);
            if !self.wait_bsy_clear() {
                return false;
            }
            // SAFETY: see `read_sectors`.
            unsafe {
                outb(self.count(), 1);
                outb(self.lba_low(), sector_lba as u8);
                outb(self.lba_mid(), (sector_lba >> 8) as u8);
                outb(self.lba_high(), (sector_lba >> 16) as u8);
                outb(self.command(), CMD_WRITE);
                if !self.wait_drq() {
                    return false;
                }
                let (pairs, _) = sector.as_chunks::<2>();
                for pair in pairs {
                    outw(self.data(), u16::from_le_bytes([pair[0], pair[1]]));
                }
                if !self.wait_drq_clear() {
                    return false;
                }
            }
        }
        true
    }
}

/// Find the ICH7 SATA-in-IDE controller and bring up its first channel.
/// Silent when absent (the QEMU smokes have no such device) or when no
/// drive answers IDENTIFY — logging then simply stays disabled.
pub(crate) fn probe(scan: &Scan) -> Option<PciIde> {
    let Some(dev) = scan.find(ICH7_SATA_IDE.0, ICH7_SATA_IDE.1) else {
        mark(0, 0, 0, 0);
        return None;
    };
    // Firmware normally leaves I/O + bus master enabled (Linux sees
    // them set). Set them explicitly: a PIO-only path still needs the
    // channel's I/O decode turned on.
    let command = crate::pci::read32(dev.location, 0x04);
    crate::pci::write32(dev.location, 0x04, command | 0x05);

    let bar0 = crate::pci::read32(dev.location, 0x10);
    let bar1 = crate::pci::read32(dev.location, 0x14);
    if bar0 & 1 == 0 || bar1 & 1 == 0 {
        mark(1, bar0, bar1, 0);
        return None; // memory-mapped or unimplemented: not our contract
    }
    mark(2, bar0, bar1, 0);
    let cmd = (bar0 & 0xFFF8) as u16;
    let ctl = (bar1 & 0xFFFC) as u16;
    if cmd == 0 || ctl == 0 {
        return None;
    }
    let ch = PciIde {
        cmd,
        ctl,
        sectors: 0,
    };
    let (cmd_out, ctl_out) = (u32::from(cmd), u32::from(ctl));

    // IDENTIFY unit 0 with bounded polls. Packet devices and empty
    // slots fail the same way: no sector capacity, no bind.
    // SAFETY: PCI BAR I/O ports; single-core boot, IRQ masked.
    let id = unsafe {
        ch.select(0, 0);
        if !ch.wait_bsy_clear() {
            mark(2, cmd_out, ctl_out, 0);
            return None;
        }
        outb(ch.command(), CMD_IDENTIFY);
        if !ch.wait_drq() {
            mark(2, cmd_out, ctl_out, 0);
            return None;
        }
        let mut words = [0u16; 256];
        for word in &mut words {
            *word = inw(ch.data());
        }
        if inb(ch.status()) & ST_ERR != 0 {
            mark(2, cmd_out, ctl_out, 0);
            return None;
        }
        words
    };
    if id[0] & 0x8000 != 0 {
        mark(2, cmd_out, ctl_out, 0);
        return None;
    }
    let sectors = u32::from(id[60]) | (u32::from(id[61]) << 16);
    if sectors == 0 {
        mark(3, cmd_out, ctl_out, 0);
        return None;
    }
    mark(4, cmd_out, ctl_out, sectors);
    Some(PciIde { sectors, ..ch })
}
