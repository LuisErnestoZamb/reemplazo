//! PxIS / PxTFD decoding: the error taxonomy a command's completion is
//! judged against.
//!
//! Sources: AHCI 1.3.1 §3.3.8 (PxIS, Table 7 in the 1.3.1 errata) and
//! §3.3.6 (PxTFD); QEMU 10.0.13 `hw/ide/ahci-internal.h`
//! (`enum AHCIPortIRQ`, `PORT_IRQ_*`) — its bit numbers are the same
//! table, and they are what the smoke test's emulated HBA raises.

use crate::reg::{TFD_BSY, TFD_DRQ, TFD_ERR, TFD_ERROR_SHIFT};

/// PxIS[0] DHRS: a D2H Register FIS arrived (normal completion).
pub const IS_DHRS: u32 = 1 << 0;
/// PxIS[1] PSS: PIO Setup FIS.
pub const IS_PSS: u32 = 1 << 1;
/// PxIS[2] DSS: DMA Setup FIS.
pub const IS_DSS: u32 = 1 << 2;
/// PxIS[3] SDBS: Set Device Bits FIS.
pub const IS_SDBS: u32 = 1 << 3;
/// PxIS[4] UFS: unknown FIS received.
pub const IS_UFS: u32 = 1 << 4;
/// PxIS[5] DPS: descriptor processed.
pub const IS_DPS: u32 = 1 << 5;
/// PxIS[6] PCS: port connect change.
pub const IS_PCS: u32 = 1 << 6;
/// PxIS[7] DMPS: device mechanical presence.
pub const IS_DMPS: u32 = 1 << 7;
/// PxIS[22] PRCS: PHY ready change.
pub const IS_PRCS: u32 = 1 << 22;
/// PxIS[23] IPMS: incorrect port multiplier.
pub const IS_IPMS: u32 = 1 << 23;
/// PxIS[24] OFS: overflow (transfer larger than the PRDT describes).
pub const IS_OFS: u32 = 1 << 24;
/// PxIS[26] INFS: interface non-fatal error.
pub const IS_INFS: u32 = 1 << 26;
/// PxIS[27] IFS: interface fatal error.
pub const IS_IFS: u32 = 1 << 27;
/// PxIS[28] HBDS: host bus data error.
pub const IS_HBDS: u32 = 1 << 28;
/// PxIS[29] HBFS: host bus fatal error.
pub const IS_HBFS: u32 = 1 << 29;
/// PxIS[30] TFES: task file error (the device set PxTFD.ERR).
pub const IS_TFES: u32 = 1 << 30;
/// PxIS[31] CPDS: cold presence detect.
pub const IS_CPDS: u32 = 1 << 31;

/// Every bit that means "this command (or the link) failed". TFES is
/// the device's own ERR; the host-bus/interface/overflow bits mean the
/// HBA could not move the data. IPMS is included because a port
/// multiplier the driver did not ask for is a failed transfer.
///
/// Deliberately **not** included: DHRS/PSS/DSS/SDBS (normal completion
/// FISes), UFS (the HBA ignores unknown FISes), PCS/PRCS/DMPS/CPDS
/// (hot-plug notifications, not command status).
pub const IS_ERROR: u32 = IS_TFES | IS_HBFS | IS_HBDS | IS_IFS | IS_INFS | IS_OFS | IS_IPMS;

/// Which PxIS error bits were set, as a name for the serial log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortError {
    /// The device reported a task-file error (PxTFD.ERR; PxIS.TFES).
    TaskFile,
    /// Host bus fatal error (PxIS.HBFS).
    HostBusFatal,
    /// Host bus data error (PxIS.HBDS).
    HostBusData,
    /// Interface fatal error (PxIS.IFS).
    InterfaceFatal,
    /// Interface non-fatal error (PxIS.INFS).
    InterfaceNonFatal,
    /// PRDT did not describe the whole transfer (PxIS.OFS).
    Overflow,
    /// Incorrect port multiplier (PxIS.IPMS).
    IncorrectPortMultiplier,
}

impl PortError {
    /// Stable human name for `serial_println!` (no `Debug` formatting of
    /// hardware data on the console).
    pub fn as_str(self) -> &'static str {
        match self {
            PortError::TaskFile => "task-file error",
            PortError::HostBusFatal => "host bus fatal error",
            PortError::HostBusData => "host bus data error",
            PortError::InterfaceFatal => "interface fatal error",
            PortError::InterfaceNonFatal => "interface non-fatal error",
            PortError::Overflow => "PRDT overflow",
            PortError::IncorrectPortMultiplier => "incorrect port multiplier",
        }
    }
}

/// First (most actionable) error encoded in `is`; `None` when no error
/// bit is set. Task-file first: on a device-side error the host bits
/// are usually clear, and the device's ERR is the real cause.
pub fn first_error(is: u32) -> Option<PortError> {
    let table = [
        (IS_TFES, PortError::TaskFile),
        (IS_HBFS, PortError::HostBusFatal),
        (IS_HBDS, PortError::HostBusData),
        (IS_IFS, PortError::InterfaceFatal),
        (IS_INFS, PortError::InterfaceNonFatal),
        (IS_OFS, PortError::Overflow),
        (IS_IPMS, PortError::IncorrectPortMultiplier),
    ];
    table
        .iter()
        .find(|(bit, _)| is & bit != 0)
        .map(|&(_, err)| err)
}

/// ATA error-register bits, carried in PxTFD[15:8] (ATA8-ACS2 §7.1
/// "Error register"; AHCI 1.3.1 §3.3.6).
pub const ATA_ERR_AMNF: u8 = 1 << 0;
pub const ATA_ERR_TK0NF: u8 = 1 << 1;
pub const ATA_ERR_ABRT: u8 = 1 << 2;
pub const ATA_ERR_MCR: u8 = 1 << 3;
pub const ATA_ERR_IDNF: u8 = 1 << 4;
pub const ATA_ERR_MC: u8 = 1 << 5;
pub const ATA_ERR_UNC: u8 = 1 << 6;
pub const ATA_ERR_BBK: u8 = 1 << 7;

/// Name of the first set bit of an ATA error byte (logs only).
pub fn taskfile_error_name(error: u8) -> &'static str {
    let table = [
        (ATA_ERR_AMNF, "address mark not found"),
        (ATA_ERR_TK0NF, "track 0 not found"),
        (ATA_ERR_ABRT, "command aborted"),
        (ATA_ERR_MCR, "media change request"),
        (ATA_ERR_IDNF, "ID not found"),
        (ATA_ERR_MC, "media changed"),
        (ATA_ERR_UNC, "uncorrectable data error"),
        (ATA_ERR_BBK, "bad block"),
    ];
    table
        .iter()
        .find(|(bit, _)| error & bit != 0)
        .map_or("unknown error", |&(_, name)| name)
}

/// PxTFD decoded as (status, error) — the ATA task-file view the device
/// last presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskFile {
    /// PxTFD[7:0].
    pub status: u8,
    /// PxTFD[15:8].
    pub error: u8,
}

impl TaskFile {
    /// Decode the raw PxTFD register value.
    pub fn from_tfd(tfd: u32) -> Self {
        TaskFile {
            status: tfd as u8,
            error: (tfd >> TFD_ERROR_SHIFT) as u8,
        }
    }

    /// ERR set: the device refused or failed the command.
    pub fn err(&self) -> bool {
        u32::from(self.status) & TFD_ERR != 0
    }

    /// DRQ set: the device has data to hand over.
    pub fn drq(&self) -> bool {
        u32::from(self.status) & TFD_DRQ != 0
    }

    /// BSY set: the device is busy.
    pub fn bsy(&self) -> bool {
        u32::from(self.status) & TFD_BSY != 0
    }

    /// A completed command: neither busy nor error.
    pub fn idle_ok(&self) -> bool {
        !self.bsy() && !self.err()
    }
}
