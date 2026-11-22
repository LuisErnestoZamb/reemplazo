//! FIS construction: the Register Host to Device FIS is the only FIS
//! this driver *builds* (the received-FIS area is device-to-host).
//!
//! Sources: *Serial ATA 3.2* §10.3.1 "Register Host to Device FIS"
//! (field layout of the 20-byte payload), reproduced by AHCI 1.3.1
//! §4.2.1 (the command table's `CFIS` area holds "the first FIS the HBA
//! delivers to the device") and QEMU 10.0.13 `hw/ide/ahci.c`
//! `handle_reg_h2d_fis()`, which decodes exactly these byte offsets:
//! `cmd_fis[1]` C|PMP, `[2]` command, `[3]` feature low,
//! `[4..7]` LBA 7:0/15:8/23:16, `[7]` device, `[8..11]` LBA
//! 31:24/39:32/47:40 (HOB), `[11]` feature high, `[12..14]` count,
//! `[15]` control.
//!
//! ATA commands (ATA8-ACS2): `IDENTIFY DEVICE` 0xEC (§7.16),
//! `READ DMA EXT` 0x25 (§7.20), `WRITE DMA EXT` 0x35 (§7.62),
//! `READ FPDMA QUEUED` 0x60 / `WRITE FPDMA QUEUED` 0x61 (§7.30/§7.31 —
//! NCQ, named here for the roadmap; this driver issues one non-NCQ
//! command at a time).

/// Register Host to Device FIS type (SATA 3.2 §10.3.1).
pub const TYPE_H2D: u8 = 0x27;
/// Register Device to Host FIS type (received-FIS area layout, SATA 3.2
/// §10.3.2).
pub const TYPE_D2H: u8 = 0x34;
/// PIO Setup FIS type (SATA 3.2 §10.3.3).
pub const TYPE_PIO_SETUP: u8 = 0x5F;
/// Set Device Bits FIS type (SATA 3.2 §10.3.5).
pub const TYPE_SDB: u8 = 0xA1;
/// FIS byte 1 bit 7: C — update the device's command register.
pub const FIS_C: u8 = 0x80;
/// FIS device byte bit 6: LBA mode (ATA8-ACS2 §7.9 "Device register").
pub const DEVICE_LBA: u8 = 0x40;

/// `IDENTIFY DEVICE` — returns the 512-byte device parameter block
/// (ATA8-ACS2 §7.16).
pub const CMD_IDENTIFY_DEVICE: u8 = 0xEC;
/// `READ DMA EXT` — LBA48 DMA read (ATA8-ACS2 §7.20).
pub const CMD_READ_DMA_EXT: u8 = 0x25;
/// `WRITE DMA EXT` — LBA48 DMA write (ATA8-ACS2 §7.62).
pub const CMD_WRITE_DMA_EXT: u8 = 0x35;
/// `READ FPDMA QUEUED` — NCQ read (ATA8-ACS2 §7.30). Not issued yet.
pub const CMD_READ_FPDMA_QUEUED: u8 = 0x60;
/// `WRITE FPDMA QUEUED` — NCQ write (ATA8-ACS2 §7.31). Not issued yet.
pub const CMD_WRITE_FPDMA_QUEUED: u8 = 0x61;

/// LBA48 window: 48 bits of addressable sectors (ATA8-ACS2 §4.14).
pub const MAX_LBA48: u64 = 1 << 48;

/// A Register Host to Device FIS payload (SATA 3.2 §10.3.1). Fixed
/// 20 bytes; the command table reserves 64 for it (AHCI 1.3.1 §4.2.1).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct H2dFis {
    bytes: [u8; 20],
}

impl H2dFis {
    /// Build one FIS. `features` lands in feature low/high (bytes 3 and
    /// 11), which `READ/WRITE DMA EXT` ignore (they must be 0 there) and
    /// which a future `SET FEATURES` would use.
    ///
    /// `None` for an LBA outside the 48-bit window or a zero sector
    /// count — both are caller bugs this function refuses to encode,
    /// so no invented value can reach a device.
    pub fn new(command: u8, lba: u64, count: u16, device: u8, features: u16) -> Option<Self> {
        if lba >= MAX_LBA48 || count == 0 {
            return None;
        }
        let mut bytes = [0u8; 20];
        bytes[0] = TYPE_H2D;
        bytes[1] = FIS_C; // C = 1, PMP = 0 (ports 0..=14 only)
        bytes[2] = command;
        bytes[3] = features as u8;
        bytes[4] = lba as u8; // LBA 7:0
        bytes[5] = (lba >> 8) as u8; // LBA 15:8
        bytes[6] = (lba >> 16) as u8; // LBA 23:16
        bytes[7] = device; // LBA 27:24 for LBA28; 0x40 for LBA48
        bytes[8] = (lba >> 24) as u8; // LBA 31:24
        bytes[9] = (lba >> 32) as u8; // LBA 39:32
        bytes[10] = (lba >> 40) as u8; // LBA 47:40
        bytes[11] = (features >> 8) as u8;
        bytes[12] = count as u8; // count 7:0
        bytes[13] = (count >> 8) as u8; // count 15:8
        bytes[14] = 0; // ICC: no isochronous command
        bytes[15] = 0; // control: no SRST, no nIEN
        Some(H2dFis { bytes })
    }

    /// `IDENTIFY DEVICE` with no address (LBA mode bit set so a device
    /// that cares sees a 48-bit-capable host).
    pub fn identify() -> Self {
        // 0xEC ignores the address/count registers; `new` requires a
        // count, so pass 1 and the LBA-mode device byte.
        match H2dFis::new(CMD_IDENTIFY_DEVICE, 0, 1, DEVICE_LBA, 0) {
            Some(fis) => fis,
            // Unreachable: lba 0 < 2^48 and count 1 != 0.
            None => H2dFis { bytes: [0; 20] },
        }
    }

    /// `READ DMA EXT` of `sectors` (1..=65535) at LBA48 `lba`.
    pub fn read_dma_ext(lba: u64, sectors: u16) -> Option<Self> {
        H2dFis::new(CMD_READ_DMA_EXT, lba, sectors, DEVICE_LBA, 0)
    }

    /// `WRITE DMA EXT` of `sectors` (1..=65535) at LBA48 `lba`.
    pub fn write_dma_ext(lba: u64, sectors: u16) -> Option<Self> {
        H2dFis::new(CMD_WRITE_DMA_EXT, lba, sectors, DEVICE_LBA, 0)
    }

    /// The 20 payload bytes, ready to be copied to the command table's
    /// `CFIS` area (offset 0x00).
    pub fn bytes(&self) -> &[u8; 20] {
        &self.bytes
    }

    /// Command register byte (FIS byte 2).
    pub fn command(&self) -> u8 {
        self.bytes[2]
    }

    /// Sector count from count low/high (FIS bytes 12/13).
    pub fn count(&self) -> u16 {
        u16::from(self.bytes[12]) | (u16::from(self.bytes[13]) << 8)
    }

    /// LBA reconstructed from the six address bytes.
    pub fn lba(&self) -> u64 {
        let b = &self.bytes;
        u64::from(b[4])
            | (u64::from(b[5]) << 8)
            | (u64::from(b[6]) << 16)
            | (u64::from(b[8]) << 24)
            | (u64::from(b[9]) << 32)
            | (u64::from(b[10]) << 40)
    }

    /// Number of dwords the HBA must fetch from `CFIS` — 5 for this
    /// 20-byte FIS, the value PxCMD/command-header field CFL takes
    /// (AHCI 1.3.1 §4.2.2: CFL is in dwords).
    pub fn cfl(&self) -> u8 {
        (self.bytes.len() / 4) as u8
    }
}
