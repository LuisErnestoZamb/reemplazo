//! Pure wire logic for the AHCI (SATA Advanced Host Controller
//! Interface) disk driver — the MacBook2,1's ICH7 disk path
//! (AGENTS.md, docs/hardware.md "AHCI").
//!
//! Everything about the controller that can be decided without touching
//! hardware lives here: the HBA/port register map ([`reg`]), PxIS/PxTFD
//! decoding ([`status`]), Register H2D FIS construction ([`fis`]), the
//! command-header / command-table / PRDT layouts and builders ([`cmd`]),
//! and transfer geometry plus IDENTIFY DEVICE decoding ([`geometry`]).
//! The MMIO and DMA `unsafe` glue lives in `kernel/src/ahci.rs` (the
//! project's `unsafe`-budget rule).
//!
//! **Sources — no offset, bit or layout here is remembered:**
//!
//! - *Serial ATA Advanced Host Controller Interface (AHCI) 1.3.1*,
//!   Intel, October 2011: §3.1 (generic host control), §3.3 (port
//!   registers), §4.2 (command list/header/table), §4.3 (PRDT).
//! - *Serial ATA 3.2* §10.3 (FIS layouts: register H2D, D2H, PIO
//!   setup, Set Device Bits).
//! - *ATA8-ACS2* §7.1 (error register), §7.16 (IDENTIFY DEVICE),
//!   §7.20 (READ DMA EXT), §7.62 (WRITE DMA EXT), §7.30/§7.31
//!   (READ/WRITE FPDMA QUEUED — NCQ, roadmap only), §4.14 (LBA48).
//! - PCI Local Bus Spec 3.0 §6.2.5.1 (BAR layout; class 01h/06h/01h).
//! - QEMU 10.0.13 (the emulator the smoke test runs)
//!   `hw/ide/ahci-internal.h` + `hw/ide/ahci.c`: `enum AHCIHostReg`,
//!   `enum AHCIPortReg`, `PORT_CMD_*`, `PORT_IRQ_*`, `AHCICmdHdr`,
//!   `AHCI_SG`, `SATA_SIGNATURE_DISK`, `AHCI_CMD_TBL_HDR_SZ`,
//!   `AHCI_PRDT_SIZE_MASK`, `handle_reg_h2d_fis()`,
//!   `ahci_populate_sglist()`.
//!
//! Dependency-policy note (recorded in the commit): this is driver
//! glue over a published hardware interface, not cryptography, so it is
//! written from scratch under exception (a) — there is no maintained
//! `no_std` AHCI crate, and the register-level truth (the AHCI spec,
//! cross-checked against QEMU) is the best reference. Zero
//! dependencies, `no_std`, `forbid(unsafe_code)`, adversarially
//! host-tested in `tests/hostile.rs`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod cmd;
pub mod fis;
pub mod geometry;
pub mod reg;
pub mod status;

/// 4 KiB: the page/frame both the kernel allocator and the DMA buffers
/// use (`memory::FRAME_SIZE`; asserted equal in `kernel/src/ahci.rs`).
pub const FRAME_BYTES: usize = 4096;

/// 512-byte logical sector (ATA8-ACS2 §3.2) — re-exported here because
/// the kernel's block trait and the wire geometry both speak sectors.
pub const SECTOR_BYTES: usize = geometry::SECTOR_BYTES;
