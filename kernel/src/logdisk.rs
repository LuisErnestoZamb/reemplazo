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
static mut ENABLED: bool = false;
static mut SEQ: u32 = 0;
/// Phase codes recorded before the disk is probed, replayed in order by
/// `init`. This is what makes a reset *before* the PCI scan diagnosable.
const EARLY_CAP: usize = 32;
static mut EARLY: [u8; EARLY_CAP] = [0; EARLY_CAP];
static mut EARLY_LEN: usize = 0;

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

fn base_lba(disk: &ata::Disk) -> Option<u32> {
    disk.sectors().checked_sub(LOG_LBA_FROM_END)
}

/// Bind the boot's already-probed disk and enable logging only when the
/// region was explicitly provisioned. A failed read or a missing magic
/// leaves the module inert: no sector is ever written.
pub fn init(disk: &ata::Disk) {
    let Some(base) = base_lba(disk) else {
        return;
    };
    let mut header = [0u8; 512];
    if !disk.read_sectors(base, &mut header) {
        return;
    }
    if &header[..16] != HEADER_MAGIC {
        return;
    }
    // SAFETY: single-core boot; no IRQ handler touches these statics and
    // `disk` is a live borrow from kernel_main's stack for the whole boot.
    unsafe {
        DISK = disk;
        ENABLED = true;
        SEQ = 0;
    }
    serial_println!("log: provisioned at LBA {base} on {}", disk.transport());
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
}

pub fn enabled() -> bool {
    unsafe { ENABLED }
}

/// Append one 512-byte record. `code` is a stable phase id; `label` is a
/// short ASCII tag. Truncates the label and silently stops at capacity —
/// logging must never become a boot failure path.
pub fn log(code: u8, label: &[u8]) {
    let (on, ptr) = unsafe { (ENABLED, DISK) };
    if !on || ptr.is_null() {
        return;
    }
    // SAFETY: see `init` — the borrowed disk outlives this call.
    let disk = unsafe { &*ptr };
    let Some(base) = base_lba(disk) else {
        return;
    };
    let seq = unsafe { SEQ };
    if seq >= LOG_SECTORS - 1 {
        return;
    }
    let mut buf = [0u8; 512];
    buf[..8].copy_from_slice(RECORD_MAGIC);
    buf[8..12].copy_from_slice(&seq.to_le_bytes());
    buf[12] = code;
    let now = crate::clock::now_ms().to_le_bytes();
    buf[16..24].copy_from_slice(&now[..8]);
    let n = label.len().min(LABEL_LEN);
    buf[24..24 + n].copy_from_slice(&label[..n]);
    if disk.write_sectors(base + 1 + seq, &buf) {
        unsafe { SEQ += 1 };
    }
}

/// Read record `seq` into `out` (caller passes 512 bytes). Returns false
/// when the log is off, the index is out of range or the disk read fails.
pub fn read(seq: u32, out: &mut [u8; 512]) -> bool {
    let (on, ptr) = unsafe { (ENABLED, DISK) };
    if !on || ptr.is_null() || seq >= LOG_SECTORS - 1 {
        return false;
    }
    // SAFETY: see `init`.
    let disk = unsafe { &*ptr };
    let Some(base) = base_lba(disk) else {
        return false;
    };
    if !disk.read_sectors(base + 1 + seq, out) {
        return false;
    }
    &out[..8] == RECORD_MAGIC
}
