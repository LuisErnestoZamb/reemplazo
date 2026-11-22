//! Command list header, command table and PRDT entry layout/builders.
//!
//! Sources: AHCI 1.3.1 §4.2 "Port Command List" — §4.2.1 (command
//! list: 32 slots of 32 bytes, 1 KiB-aligned), §4.2.2 (command header
//! dwords: CFL[4:0], A[5], W[6], P[7], R[8], B[9], C[10],
//! PMP[15:12], PRDTL[31:16]; PRDBC in dword 1; CTBA in dwords 2/3,
//! 128-byte aligned), §4.2.3 (command table: CFIS 0x00..0x40, ACMD
//! 0x40..0x50, reserved to 0x80, PRDT from 0x80), §4.3 (PRDT entry:
//! DBA dword 0, DBAU dword 1, reserved dword 2, DBC/I dword 3 —
//! DBC[21:0] is byte count minus one, bit 31 = interrupt on completion).
//! QEMU 10.0.13 `hw/ide/ahci-internal.h` (`AHCICmdHdr`, `AHCI_SG`,
//! `AHCI_CMD_TBL_HDR_SZ` 0x80, `AHCI_PRDT_SIZE_MASK` 0x3fffff,
//! `AHCI_CMD_HDR_CMD_FIS_LEN`, `AHCI_CMD_WRITE`) and `ahci.c`'s
//! `ahci_populate_sglist()` agree field for field.

use core::mem::size_of;

/// One command header is 32 bytes (AHCI 1.3.1 §4.2.1).
pub const HEADER_BYTES: usize = 32;
/// The command list is 32 slots (AHCI 1.3.1 §4.2.1).
pub const HEADER_SLOTS: usize = 32;
/// … i.e. exactly 1 KiB, and PxCLB must be 1 KiB-aligned.
pub const LIST_BYTES: usize = HEADER_BYTES * HEADER_SLOTS;
/// PxCLB alignment (AHCI 1.3.1 §3.3.1).
pub const LIST_ALIGN: usize = 1024;
/// PxFB: received-FIS area, 256 bytes, 256-byte aligned (AHCI 1.3.1
/// §3.3.3).
pub const FIS_BYTES: usize = 256;
pub const FIS_ALIGN: usize = 256;
/// CTBA alignment (AHCI 1.3.1 §4.2.2).
pub const TABLE_ALIGN: usize = 128;
/// CFIS area: 0x00..0x40 (AHCI 1.3.1 §4.2.3).
pub const TABLE_CFIS: usize = 0x00;
/// ACMD (ATAPI packet) area.
pub const TABLE_ACMD: usize = 0x40;
/// PRDT starts at offset 0x80 of the command table.
pub const TABLE_PRDT: usize = 0x80;
/// One PRDT entry is 16 bytes (AHCI 1.3.1 §4.3).
pub const PRDT_ENTRY_BYTES: usize = 16;
/// PRDTL is a 16-bit field: at most 65535 entries (AHCI 1.3.1 §4.2.2).
pub const MAX_PRDT_ENTRIES: usize = 65535;
/// DBC is 22 bits of "byte count minus one" → at most 4 MiB per entry
/// (AHCI 1.3.1 §4.3; QEMU `AHCI_PRDT_SIZE_MASK` 0x3f_ffff).
pub const PRDT_MAX_BYTES: usize = 1 << 22;
/// Interrupt-on-completion bit of a PRDT entry's DBC dword.
pub const PRDT_INTERRUPT: u32 = 1 << 31;

/// CFL for a 20-byte Register H2D FIS (5 dwords).
pub const CFL_H2D: u8 = 5;
/// The HBA accepts CFL 2..=16 (AHCI 1.3.1 §4.2.2; QEMU refuses
/// `cfl < 2 || cfl > 16` in `handle_cmd()`).
pub const CFL_MIN: u8 = 2;
pub const CFL_MAX: u8 = 16;

// --- Command header (AHCI 1.3.1 §4.2.2) -----------------------------------
/// dw0 bit 5: A — ATAPI command.
pub const HDR_ATAPI: u32 = 1 << 5;
/// dw0 bit 6: W — data direction is device→host? No: W = 1 means
/// *host to device* (write); see AHCI 1.3.1 §4.2.2 and QEMU
/// `AHCI_CMD_WRITE`.
pub const HDR_WRITE: u32 = 1 << 6;
/// dw0 bit 7: P — prefetchable.
pub const HDR_PREFETCH: u32 = 1 << 7;

/// The four dwords of a command header this driver fills (dwords 0..3;
/// dword 0 carries CFL, W and PRDTL, dword 1 PRDBC, dwords 2/3 CTBA).
///
/// `None` for a CFL the HBA refuses, a PRDTL over the 16-bit field or a
/// misaligned command-table address — fail-closed construction, so a
/// bug cannot program the HBA with a value the spec calls illegal.
pub fn header_dwords(cfl: u8, write: bool, prdtl: u16, table: u64) -> Option<[u32; 4]> {
    if !(CFL_MIN..=CFL_MAX).contains(&cfl) || table & (TABLE_ALIGN as u64 - 1) != 0 {
        return None;
    }
    let dw0 = u32::from(cfl) | if write { HDR_WRITE } else { 0 } | (u32::from(prdtl) << 16);
    Some([dw0, 0, table as u32, (table >> 32) as u32])
}

/// The PRDT entry that describes `len` bytes at physical address
/// `base`: DBA/DBAU (low/high 32 bits), reserved, then
/// `DBC = len - 1` plus the optional interrupt bit.
///
/// `None` for an empty/oversized entry or a base the HBA would reject
/// (DBA[1:0] must be 0 — AHCI 1.3.1 §4.3).
pub fn prdt_dwords(base: u64, len: usize, interrupt: bool) -> Option<[u32; 4]> {
    if len == 0 || len > PRDT_MAX_BYTES || base & 0b11 != 0 {
        return None;
    }
    let dbc = (len as u32 - 1) | if interrupt { PRDT_INTERRUPT } else { 0 };
    Some([base as u32, (base >> 32) as u32, 0, dbc])
}

// --- Hardware ABI structs (layout asserted at compile time) ---------------

/// Command header as it sits in the 1 KiB command-list frame.
/// `#[repr(C)]` field order and padding are the hardware ABI.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    /// dw0 low half: CFL[4:0] | A[5] | W[6] | P[7] | R[8] | B[9] | C[10]
    /// | reserved[11] | PMP[15:12].
    pub opts: u16,
    /// dw0 high half: PRDTL[31:16].
    pub prdtl: u16,
    /// dw1: PRDBC, bytes the HBA transferred (written by the HBA).
    pub prdbc: u32,
    /// dw2/dw3: CTBA.
    pub table: u64,
    /// dw4..dw7: reserved.
    pub reserved: [u32; 4],
}

/// One PRDT entry (AHCI 1.3.1 §4.3 / QEMU `AHCI_SG`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PrdtEntry {
    /// DBA: data base address, low 32 bits (DBA[1:0] = 0).
    pub dba: u32,
    /// DBAU: data base address, high 32 bits.
    pub dbau: u32,
    /// Reserved.
    pub reserved: u32,
    /// DBC[21:0] = byte count - 1; bit 31 = I (interrupt on completion).
    pub dbc: u32,
}

// These are hardware layouts: a compiler that changes them is a bug we
// catch at build time, not in the field.
const _: () = assert!(size_of::<CommandHeader>() == HEADER_BYTES);
const _: () = assert!(size_of::<PrdtEntry>() == PRDT_ENTRY_BYTES);
const _: () = assert!(size_of::<PrdtEntry>() * MAX_PRDT_ENTRIES == 0x10_0000 - 16);
