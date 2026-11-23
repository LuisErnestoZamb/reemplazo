//! User-facing persistent log syscalls (bring-up application support).
//!
//! The disk driver and the on-disk record layout stay in ring 0
//! (`crate::logdisk`): there is no IOMMU on the ICH7, so a CPL3 process
//! cannot own the DMA engine. These two calls only move bounded ASCII
//! payloads across the syscall boundary; all validation is inherited
//! from `userptr`, the same gate the filesystem syscalls use.
//!
//! Numbers 28/29 continue the stable ABI in `docs/syscall-abi.md`.

use super::syscall::EINVAL;
use super::userptr;

/// `log_write(buf, len) -> i64` — append one record, `0` or `-EINVAL`.
pub const NR_LOG_WRITE: u64 = 28;
/// `log_read(seq, buf, len) -> i64` — read one 512-byte record, `-EINVAL`
/// when disabled, out of range or malformed.
pub const NR_LOG_READ: u64 = 29;

const RECORD_LEN: usize = 512;

fn sys_log_write(buf: u64, len: u64) -> i64 {
    if len == 0 || len > 112 {
        return EINVAL;
    }
    let Ok(bytes) = userptr::validated_slice(buf, len as usize) else {
        return EINVAL;
    };
    if !crate::logdisk::enabled() {
        return EINVAL;
    }
    crate::logdisk::log(0xE0, bytes);
    0
}

fn sys_log_read(seq: u64, buf: u64, len: u64) -> i64 {
    if len != RECORD_LEN as u64 {
        return EINVAL;
    }
    if let Err(e) = userptr::validate(buf, RECORD_LEN) {
        return e;
    }
    let mut record = [0u8; RECORD_LEN];
    if !crate::logdisk::read(seq as u32, &mut record) {
        return EINVAL;
    }
    // SAFETY: `userptr::validate` proved the whole 512-byte window is a
    // registered user VMA inside the user address region; single core,
    // IF=0 in the int 0x80 gate, so no concurrent mutation is possible.
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, RECORD_LEN) };
    out.copy_from_slice(&record);
    RECORD_LEN as i64
}

/// Additive dispatch hook, chained from `syscall::dispatch_inner`.
pub fn dispatch_log(nr: u64, args: [u64; 6]) -> Option<i64> {
    match nr {
        NR_LOG_WRITE => Some(sys_log_write(args[0], args[1])),
        NR_LOG_READ => Some(sys_log_read(args[0], args[1], args[2])),
        _ => None,
    }
}
