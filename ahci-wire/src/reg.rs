//! HBA and per-port register map: offsets, bit positions and decoders.
//!
//! **Sources (nothing here is remembered):**
//!
//! - *Serial ATA Advanced Host Controller Interface (AHCI) 1.3.1*,
//!   Intel, October 2011 — §3.1 "Generic Host Control" (Table 3:
//!   CAP/GHC/IS/PI/VS at 0x00/0x04/0x08/0x0C/0x10), §3.3 "Port
//!   Registers" (PxCLB…PxFBS at 0x00…0x40 of every 0x80-byte port
//!   window starting at 0x100), §3.3.2 PxCMD (Table 10), §3.3.6 PxTFD,
//!   §3.3.7 PxSIG (Table 12 signature values), §3.3.8 PxSSTS, §3.3.9
//!   PxSCTL, §3.3.10 PxSERR.
//! - QEMU 10.0.13 `hw/ide/ahci-internal.h` + `hw/ide/ahci.c` (the
//!   emulator this repository's smoke test runs): `enum AHCIHostReg`,
//!   `enum AHCIPortReg`, `AHCI_PORT_REGS_START_ADDR` 0x100,
//!   `AHCI_PORT_ADDR_OFFSET_LEN` 0x80, `AHCI_MAX_PORTS` 32,
//!   `HOST_CTL_*`, `PORT_CMD_*`, `SATA_SIGNATURE_DISK` 0x00000101,
//!   `SATA_SCR_SSTATUS_*`, `AHCI_SCR_SCTL_DET`, `PORT_IRQ_*`.
//! - PCI Local Bus Spec 3.0 §6.2.5.1 (BAR layout): the class code this
//!   driver looks for is 01h/06h/01h (mass storage / SATA / AHCI
//!   programming interface), BAR5 = offset 0x24 (ABAR).

// ---------------------------------------------------------------------------
// PCI: where the controller is and how to enable it
// ---------------------------------------------------------------------------

/// PCI class code for a mass-storage controller (PCI spec, base class 01h).
pub const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
/// Sub-class 06h = SATA controller (PCI spec; AHCI 1.3.1 §2.1.7).
pub const PCI_SUBCLASS_SATA: u8 = 0x06;
/// Programming interface 01h = AHCI mode (PCI spec; AHCI 1.3.1 §2.1.7).
pub const PCI_PROG_IF_AHCI: u8 = 0x01;
/// BAR5 (ABAR) is config-space offset 0x24 and BAR6 (its upper half when
/// the BAR is 64-bit) is 0x28 (PCI spec §6.2.5.1; AHCI 1.3.1 §2.1.8).
pub const PCI_BAR5: u8 = 0x24;
pub const PCI_BAR6: u8 = 0x28;

// ---------------------------------------------------------------------------
// Generic Host Control (AHCI 1.3.1 §3.1, Table 3)
// ---------------------------------------------------------------------------

/// Host Capabilities.
pub const HBA_CAP: u32 = 0x00;
/// Global Host Control.
pub const HBA_GHC: u32 = 0x04;
/// Interrupt Status.
pub const HBA_IS: u32 = 0x08;
/// Ports Implemented (one bit per port).
pub const HBA_PI: u32 = 0x0C;
/// Version.
pub const HBA_VS: u32 = 0x10;
/// BIOS/OS Handoff Control and Status (AHCI 1.3.1 §3.1.11).
pub const HBA_BOHC: u32 = 0x28;

/// CAP[12:8] = number of command slots minus one (AHCI 1.3.1 §3.1.1).
pub const CAP_NCS_MASK: u32 = 0x0000_1F00;
/// CAP[12:8] shift.
pub const CAP_NCS_SHIFT: u32 = 8;
/// CAP[31] = 64-bit addressing supported (AHCI 1.3.1 §3.1.1).
pub const CAP_S64A: u32 = 1 << 31;

/// Command slots this HBA supports, 1..=32 (CAP.NCS is 0-based).
pub fn command_slots(cap: u32) -> u8 {
    ((cap & CAP_NCS_MASK) >> CAP_NCS_SHIFT) as u8 + 1
}

/// GHC[31] AE: AHCI enable (AHCI 1.3.1 §3.1.2).
pub const GHC_AE: u32 = 1 << 31;
/// GHC[1] IE: global interrupt enable.
pub const GHC_IE: u32 = 1 << 1;
/// GHC[0] HR: HBA reset (self-clearing).
pub const GHC_HR: u32 = 1 << 0;

/// True when `pi` (the PI register) says port `port` exists.
pub fn port_implemented(pi: u32, port: u8) -> bool {
    port < MAX_PORTS && pi & (1 << port) != 0
}

// ---------------------------------------------------------------------------
// Port registers (AHCI 1.3.1 §3.3, Table 8)
// ---------------------------------------------------------------------------

/// First port register window starts at 0x100 (AHCI 1.3.1 §3.3).
pub const PORT_REGS_BASE: u32 = 0x100;
/// Every port owns 0x80 bytes of the ABAR window (AHCI 1.3.1 §3.3).
pub const PORT_STRIDE: u32 = 0x80;
/// AHCI 1.3.1 §2.2.1 / 3.3: at most 32 ports.
pub const MAX_PORTS: u8 = 32;

/// PxCLB: command list base address (low 32 bits).
pub const PORT_CLB: u32 = 0x00;
/// PxCLBU: command list base address (high 32 bits).
pub const PORT_CLBU: u32 = 0x04;
/// PxFB: received FIS base address (low 32 bits).
pub const PORT_FB: u32 = 0x08;
/// PxFBU: received FIS base address (high 32 bits).
pub const PORT_FBU: u32 = 0x0C;
/// PxIS: interrupt status.
pub const PORT_IS: u32 = 0x10;
/// PxIE: interrupt enable.
pub const PORT_IE: u32 = 0x14;
/// PxCMD: port command and status.
pub const PORT_CMD: u32 = 0x18;
/// PxTFD: task file data (status in [7:0], error in [15:8]).
pub const PORT_TFD: u32 = 0x20;
/// PxSIG: device signature.
pub const PORT_SIG: u32 = 0x24;
/// PxSSTS: SATA status (SCR0).
pub const PORT_SSTS: u32 = 0x28;
/// PxSCTL: SATA control (SCR2).
pub const PORT_SCTL: u32 = 0x2C;
/// PxSERR: SATA error (SCR1).
pub const PORT_SERR: u32 = 0x30;
/// PxSACT: SATA active (NCQ tags).
pub const PORT_SACT: u32 = 0x34;
/// PxCI: command issue (one bit per command slot).
pub const PORT_CI: u32 = 0x38;

/// Byte offset of `reg` inside port `port`'s register window — `None`
/// for a port index outside 0..32 (hardware data, never trusted).
pub const fn port_reg(port: u8, reg: u32) -> Option<u32> {
    if port >= MAX_PORTS {
        return None;
    }
    Some(PORT_REGS_BASE + port as u32 * PORT_STRIDE + reg)
}

/// PxCMD[0] ST: start the DMA command engine (AHCI 1.3.1 §3.3.2).
pub const CMD_ST: u32 = 1 << 0;
/// PxCMD[1] SUD: spin-up device.
pub const CMD_SUD: u32 = 1 << 1;
/// PxCMD[2] POD: power on device.
pub const CMD_POD: u32 = 1 << 2;
/// PxCMD[3] CLO: command list override.
pub const CMD_CLO: u32 = 1 << 3;
/// PxCMD[4] FRE: FIS receive enable.
pub const CMD_FRE: u32 = 1 << 4;
/// PxCMD[12:8] CCS: current command slot (read-only).
pub const CMD_CCS_MASK: u32 = 0x0000_1F00;
/// PxCMD[12:8] shift.
pub const CMD_CCS_SHIFT: u32 = 8;
/// PxCMD[14] FR: FIS receive running (read-only).
pub const CMD_FR: u32 = 1 << 14;
/// PxCMD[15] CR: command list running (read-only).
pub const CMD_CR: u32 = 1 << 15;
/// Bits the HBA owns: a read-modify-write must preserve them
/// (QEMU `PORT_CMD_RO_MASK` 0x007dffe0 — same set as AHCI 1.3.1 §3.3.2).
pub const CMD_READ_ONLY_MASK: u32 = 0x007D_FFE0;

/// PxTFD[7:0] status bits (ATA status register; AHCI 1.3.1 §3.3.6).
pub const TFD_ERR: u32 = 1 << 0;
pub const TFD_DRQ: u32 = 1 << 3;
pub const TFD_BSY: u32 = 1 << 7;
/// PxTFD[15:8] is the ATA error register.
pub const TFD_ERROR_SHIFT: u32 = 8;

/// PxSIG value for a SATA drive speaking the ATA command set
/// (AHCI 1.3.1 Table 12 / QEMU `SATA_SIGNATURE_DISK`).
pub const SIG_ATA: u32 = 0x0000_0101;
/// PxSIG value for an ATAPI (packet) device — skipped by this driver.
pub const SIG_ATAPI: u32 = 0xEB14_0101;

/// PxSSTS[3:0] DET: device detection (AHCI 1.3.1 §3.3.8).
pub const SSTS_DET_MASK: u32 = 0x0F;
/// DET value 3 = device present and PHY established.
pub const SSTS_DET_PRESENT: u32 = 0x03;
/// PxSSTS[11:8] IPM: interface power management.
pub const SSTS_IPM_MASK: u32 = 0x0F00;
/// IPM value 1 = active.
pub const SSTS_IPM_ACTIVE: u32 = 0x0100;

/// PxSCTL[3:0] DET: write 1 for COMRESET, 0 for no action
/// (AHCI 1.3.1 §3.3.9).
pub const SCTL_DET_MASK: u32 = 0x0F;
/// COMRESET code.
pub const SCTL_DET_COMRESET: u32 = 0x01;

/// PxSSTS.DET says a device is attached and its PHY is up.
pub fn device_present(ssts: u32) -> bool {
    ssts & SSTS_DET_MASK == SSTS_DET_PRESENT
}
