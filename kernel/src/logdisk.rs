//! Persistent bring-up log on the raw disk (not a filesystem).
//!
//! The MacBook has no serial port and the VGA is gone after a reset, so a
//! boot that fails before userland leaves no evidence. This module writes
//! small fixed-size records to a reserved gap near the end of the disk,
//! which Debian can read back with `dd` after the watchdog reboots.
//!
//! **Gateway**: writes only happen when the first sector of that region
//! carries [`HEADER_MAGIC`], provisioned once by `xtask provisionlog`.
//! Unprovisioned disks (every QEMU smoke image, an unmodified install)
//! are completely untouched — this is why the 30-marker smoke chain is
//! unchanged by this module.
//!
//! The transport driver stays in ring 0: the ICH7 has no IOMMU, so a
//! user process cannot safely own the DMA engine. Userland reaches the
//! log through `LogWrite`/`LogRead` (syscalls 28/29) implemented in
//! `userland/log.rs`; the formatting application is `user/logger`.

use crate::ata;

/// Provisioned-region header, 16 bytes at [`base_lba`].
pub const HEADER_MAGIC: &[u8; 16] = b"REEMPLAZO-LOG-v1";
/// Per-record prefix (8 bytes), followed by seq/code/time/label.
pub const RECORD_MAGIC: &[u8; 8] = b"RLOGv1\0\0";
/// Distance from the disk's end to the provisioned region. On the
/// MacBook (234441648 sectors) this is LBA 234440708 — past the last
/// partition (sda3 ends at 234440703) and 907 sectors before the
/// backup GPT at 234441615, so neither Debian nor GRUB is disturbed.
pub const LOG_LBA_FROM_END: u32 = 940;
/// Region size including the header sector. Stops at base+899 =
/// 234441607, still before the backup GPT.
pub const LOG_SECTORS: u32 = 900;
/// ASCII label bytes in one record.
const LABEL_LEN: usize = 112;

/// Borrowed disk from `kernel_main`. Its stack slot outlives every call
/// here (kernel_main never returns), so this is valid for the whole boot.
static mut DISK: *const ata::Disk = core::ptr::null();
/// PCI-native IDE channel on the ICH7 SATA controller (the real
/// MacBook). Owned by value — `PciIde` holds only port numbers and a
/// capacity, no DMA frames — so no lifetime gymnastics are needed.
static mut PCI: crate::ata_pci::PciIde = crate::ata_pci::PciIde::ZERO;
static mut USE_PCI: bool = false;
static mut ENABLED: bool = false;
static mut SEQ: u32 = 0;
/// Random per-boot tag; lets the host reader stop at the last record
/// of the current boot instead of showing stale sectors from an older
/// one (their sequence numbers restart at 0 too).
static mut BOOT_NONCE: u16 = 0;

fn read_at(lba: u32, buf: &mut [u8; 512]) -> bool {
    // SAFETY: single-core boot; the backend is set once by init and no
    // IRQ handler touches these statics.
    unsafe {
        if USE_PCI {
            core::ptr::addr_of!(PCI).read().read_sectors(lba, buf)
        } else if !DISK.is_null() {
            (&*DISK).read_sectors(lba, buf)
        } else {
            false
        }
    }
}

fn write_at(lba: u32, buf: &[u8; 512]) -> bool {
    // SAFETY: see `read_at`.
    unsafe {
        if USE_PCI {
            core::ptr::addr_of!(PCI).read().write_sectors(lba, buf)
        } else if !DISK.is_null() {
            (&*DISK).write_sectors(lba, buf)
        } else {
            false
        }
    }
}
/// Phase codes recorded before the disk is probed, replayed in order by
/// `init`. This is what makes a reset *before* the PCI scan diagnosable.
const EARLY_CAP: usize = 32;
static mut EARLY: [u8; EARLY_CAP] = [0; EARLY_CAP];
static mut EARLY_LEN: usize = 0;

/// Bring-up diagnostics exposed over SSH (`logstatus`): how many disks
/// were tried and why the last one was rejected. 0 = ok, 1 = LBA out of
/// range, 2 = sector read failed, 3 = magic mismatch.
static mut PROBES: u32 = 0;
static mut LAST_FAIL: u8 = 0xFF;
static mut AHCI_SEEN: u32 = 0;
static mut IDE_SEEN: u32 = 0;

pub fn diagnostics() -> (u32, u8, u32, u32) {
    // SAFETY: single-core boot, these are written only during init.
    unsafe { (PROBES, LAST_FAIL, AHCI_SEEN, IDE_SEEN) }
}

pub fn note_disks(ahci: u32, ide: u32) {
    // SAFETY: see above.
    unsafe {
        AHCI_SEEN = ahci;
        IDE_SEEN = ide;
    }
}

/// Record a pre-disk phase code. Safe before `init`; replayed on it.
pub fn early(code: u8) {
    // SAFETY: single-core boot, no other caller of these statics.
    unsafe {
        if EARLY_LEN < EARLY_CAP {
            EARLY[EARLY_LEN] = code;
            EARLY_LEN += 1;
        }
    }
}

/// Bind the boot's already-probed disk (installer source). The borrow
/// lives in `kernel_main` for the whole boot.
pub fn init(disk: &ata::Disk) -> bool {
    // SAFETY: single-core boot; no IRQ handler touches these statics.
    unsafe {
        DISK = disk;
        USE_PCI = false;
    }
    init_sectors(disk.sectors(), disk.transport())
}

/// Bind a PCI-native IDE channel (ICH7 SATA-in-IDE mode). Owned by value;
/// no borrow outlives the call.
pub fn init_pci(ch: &crate::ata_pci::PciIde) -> bool {
    // SAFETY: see `init`.
    unsafe {
        PCI = *ch;
        DISK = core::ptr::null();
        USE_PCI = true;
    }
    init_sectors(ch.sectors, "pci-ide")
}

/// Enable logging only when the region carries the provisioning magic.
/// A failed read or missing magic leaves the module inert: no sector is
/// ever written.
fn init_sectors(sectors: u32, transport: &'static str) -> bool {
    unsafe { PROBES += 1 };
    let Some(base) = sectors.checked_sub(LOG_LBA_FROM_END) else {
        unsafe { LAST_FAIL = 1 };
        return false;
    };
    let mut header = [0u8; 512];
    if !read_at(base, &mut header) {
        unsafe { LAST_FAIL = 2 };
        return false;
    }
    if &header[..16] != HEADER_MAGIC {
        unsafe { LAST_FAIL = 3 };
        return false;
    }
    unsafe {
        ENABLED = true;
        SEQ = 0;
        BOOT_NONCE = (crate::entropy::boot_entropy() ^ crate::clock::now_ms() as u32) as u16;
    }
    serial_println!("log: provisioned at LBA {base} on {transport}");
    log(0x01, b"log ready");
    // SAFETY: see the single-core contract above.
    unsafe {
        let n = EARLY_LEN;
        let codes = core::ptr::addr_of!(EARLY).cast::<u8>();
        for i in 0..n {
            log(*codes.add(i), b"early phase");
        }
        EARLY_LEN = 0;
    }
    unsafe { LAST_FAIL = 0 };
    true
}

pub fn enabled() -> bool {
    unsafe { ENABLED }
}

/// Number of records accepted by the disk so far. Used by the SSH
/// bring-up probe to report the log state without a serial port.
pub fn count() -> u32 {
    unsafe { SEQ }
}

/// Append one 512-byte record. `code` is a stable phase id; `label` is a
/// short ASCII tag. Truncates the label and silently stops at capacity —
/// logging must never become a boot failure path.
fn log_base() -> Option<u32> {
    // SAFETY: single-core boot; backend set once by init.
    unsafe {
        let sectors = if USE_PCI {
            core::ptr::addr_of!(PCI).read().sectors
        } else if !DISK.is_null() {
            (&*DISK).sectors()
        } else {
            0
        };
        sectors.checked_sub(LOG_LBA_FROM_END)
    }
}

pub fn log(code: u8, label: &[u8]) {
    if !unsafe { ENABLED } {
        return;
    }
    let Some(base) = log_base() else {
        return;
    };
    let seq = unsafe { SEQ };
    if seq >= LOG_SECTORS - 1 {
        return;
    }
    let mut buf = [0u8; 512];
    buf[..8].copy_from_slice(RECORD_MAGIC);
    buf[8..12].copy_from_slice(&seq.to_le_bytes());
    buf[10..12].copy_from_slice(&unsafe { BOOT_NONCE }.to_le_bytes());
    buf[12] = code;
    let now = crate::clock::now_ms().to_le_bytes();
    buf[16..24].copy_from_slice(&now[..8]);
    let n = label.len().min(LABEL_LEN);
    buf[24..24 + n].copy_from_slice(&label[..n]);
    if write_at(base + 1 + seq, &buf) {
        unsafe { SEQ += 1 };
    }
}

/// Read record `seq` into `out` (caller passes 512 bytes). Returns false
/// when the log is off, the index is out of range or the disk read fails.
pub fn read(seq: u32, out: &mut [u8; 512]) -> bool {
    if !unsafe { ENABLED } || seq >= LOG_SECTORS - 1 {
        return false;
    }
    let Some(base) = log_base() else {
        return false;
    };
    if !read_at(base + 1 + seq, out) {
        return false;
    }
    &out[..8] == RECORD_MAGIC
}
