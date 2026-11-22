//! User filesystem syscalls (hito 4) — numbers 10..=15.
//!
//! **Additive by design.** This module never edits `syscall.rs`; it only
//! exposes [`dispatch_fs`] for the integrator's default match arm:
//!
//! ```text
//! n => crate::userland::console::dispatch_extra(n, args)
//!         .or_else(|| crate::userland::fs::dispatch_fs(n, args))
//!         .unwrap_or(ENOSYS),
//! ```
//!
//! The kernel keeps `fat` + ATA/AHCI in ring 0. User code supplies only
//! bounded buffers (checked by [`userptr`]) and receives an **opaque**
//! fd: the caller never sees a slot index, and a stale or foreign fd is
//! refused with `EINVAL`. The open-file table is indexed by the current
//! PCB's PID (the scheduler's `current_pid()`), so descriptors are per
//! process even though this file cannot touch `Process.fds` directly.
//!
//! Errnos are the ABI's existing set — `EINVAL` for a bad path/fd/flags,
//! `EFAULT` for a refused user buffer, `EPERM` for a path escape or a
//! permission violation, `ENOSYS` for an unowned number.

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};

use super::process::MAX_FDS;
use super::sched::current_pid;
use super::syscall::{EINVAL, EPERM};
use super::userptr;
use super::vfs;

// --- Stable syscall numbers (mirrored in `userlib`) ----------------------
/// `open(path: *const u8, len: u64, flags: u64) -> fd`
pub const NR_OPEN: u64 = 10;
/// `close(fd: u64) -> i64`
pub const NR_CLOSE: u64 = 11;
/// `read(fd: u64, buf: *mut u8, len: u64) -> i64`
pub const NR_READ: u64 = 12;
/// `write(fd: u64, buf: *const u8, len: u64) -> i64`
pub const NR_WRITE: u64 = 13;
/// `stat(fd: u64, out: *mut u8, len: u64) -> i64`
pub const NR_STAT: u64 = 14;
/// `readdir(fd: u64, out: *mut u8, len: u64) -> i64`
pub const NR_READDIR: u64 = 15;

// Open flags. Unknown bits are refused (fail closed), not ignored.
pub const O_RDONLY: u64 = 0;
pub const O_WRONLY: u64 = 1;
pub const O_RDWR: u64 = 2;
pub const O_CREAT: u64 = 0x40;
pub const O_TRUNC: u64 = 0x200;
pub const O_APPEND: u64 = 0x400;
const ACCESS_MASK: u64 = O_RDONLY | O_WRONLY | O_RDWR;
const FLAG_MASK: u64 = ACCESS_MASK | O_CREAT | O_TRUNC | O_APPEND;

/// Fds are tagged so a random integer (including 0/1/2 from the console
/// ABI) can never alias a volume descriptor.
const FD_TAG: u64 = 0x4000_0000;

/// One entry in the kernel-owned open file table. Nothing here is ever
/// exposed to user memory; the fd is a lookup key into this array.
struct OpenFile {
    used: AtomicU8,
    pid: AtomicU32,
    vslot: AtomicU8,
    flags: AtomicU8,
    off: AtomicUsize,
}

impl OpenFile {
    const fn new() -> Self {
        Self {
            used: AtomicU8::new(0),
            pid: AtomicU32::new(u32::MAX),
            vslot: AtomicU8::new(0),
            flags: AtomicU8::new(0),
            off: AtomicUsize::new(0),
        }
    }
}

static FILES: [OpenFile; 8 * MAX_FDS] = [const { OpenFile::new() }; 8 * MAX_FDS];

fn encode_fd(index: usize) -> u64 {
    FD_TAG | index as u64
}

fn find_fd(fd: u64, pid: u32) -> Option<usize> {
    if fd < FD_TAG {
        return None;
    }
    let index = (fd - FD_TAG) as usize;
    let entry = FILES.get(index)?;
    if entry.used.load(Ordering::Relaxed) == 0 || entry.pid.load(Ordering::Relaxed) != pid {
        return None;
    }
    Some(index)
}

fn readable(flags: u8) -> bool {
    flags & 3 == O_RDONLY as u8 || flags & 3 == O_RDWR as u8
}

fn writable(flags: u8) -> bool {
    flags & 3 == O_WRONLY as u8 || flags & 3 == O_RDWR as u8
}

fn sys_open(path_ptr: u64, path_len: u64, flags: u64) -> i64 {
    if flags & !FLAG_MASK != 0 || flags & 3 == 3 {
        return EINVAL;
    }
    if path_len == 0 || path_len > vfs::MAX_PATH as u64 {
        return EINVAL;
    }
    let bytes = match userptr::validated_slice(path_ptr, path_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if let Err(e) = vfs::check_parent(bytes) {
        return e;
    }
    let slot = match vfs::lookup(bytes) {
        Ok(s) => s,
        Err(EINVAL) if flags & O_CREAT != 0 => match vfs::create(bytes) {
            Ok(s) => s,
            Err(e) => return e,
        },
        Err(e) => return e,
    };
    if vfs::kind(slot) == Some(vfs::Kind::Dir) && flags & ACCESS_MASK != O_RDONLY {
        return EPERM;
    }
    if flags & O_TRUNC != 0 && !writable(flags as u8) {
        return EPERM;
    }
    let pid = current_pid();
    let base = (pid as usize).saturating_mul(MAX_FDS);
    for local in 0..MAX_FDS {
        let index = base + local;
        if index >= FILES.len() {
            return EPERM;
        }
        let entry = &FILES[index];
        if entry.used.load(Ordering::Relaxed) != 0 {
            continue;
        }
        let off = if flags & O_APPEND != 0 {
            vfs::size(slot)
        } else {
            0
        };
        entry.vslot.store(slot as u8, Ordering::Relaxed);
        entry.flags.store(flags as u8, Ordering::Relaxed);
        entry.off.store(off, Ordering::Relaxed);
        entry.pid.store(pid, Ordering::Relaxed);
        entry.used.store(1, Ordering::Relaxed);
        return encode_fd(index) as i64;
    }
    EPERM // per-process fd table full
}

fn sys_close(fd: u64) -> i64 {
    let Some(index) = find_fd(fd, current_pid()) else {
        return EINVAL;
    };
    FILES[index].used.store(0, Ordering::Relaxed);
    0
}

fn sys_read(fd: u64, buf: u64, len: u64) -> i64 {
    let Some(index) = find_fd(fd, current_pid()) else {
        return EINVAL;
    };
    let entry = &FILES[index];
    let flags = entry.flags.load(Ordering::Relaxed);
    if !readable(flags) {
        return EPERM;
    }
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    if len == 0 {
        return 0;
    }
    if let Err(e) = userptr::validate(buf, len as usize) {
        return e;
    }
    let off = entry.off.load(Ordering::Relaxed);
    let slot = entry.vslot.load(Ordering::Relaxed) as usize;
    // SAFETY: `userptr::validate` proved `buf..buf+len` lies wholly in one
    // registered user VMA inside the user window and within 64 KiB. The
    // CPL3 process cannot run concurrently (single core, IF=0 in the
    // int 0x80 gate), so the bytes cannot change during this copy. No
    // reference survives the syscall.
    let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) };
    let n = vfs::read(slot, off, dst);
    entry.off.store(off.saturating_add(n), Ordering::Relaxed);
    n as i64
}

fn sys_write(fd: u64, buf: u64, len: u64) -> i64 {
    let Some(index) = find_fd(fd, current_pid()) else {
        return EINVAL;
    };
    let entry = &FILES[index];
    let flags = entry.flags.load(Ordering::Relaxed);
    if !writable(flags) {
        return EPERM;
    }
    let off = if flags & O_APPEND as u8 != 0 {
        let slot = entry.vslot.load(Ordering::Relaxed) as usize;
        vfs::size(slot)
    } else {
        entry.off.load(Ordering::Relaxed)
    };
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    let bytes = match userptr::validated_slice(buf, len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    // Fail closed instead of silently truncating a full volume slot.
    if off.saturating_add(bytes.len()) > vfs::FILE_CAP {
        return EPERM;
    }
    let slot = entry.vslot.load(Ordering::Relaxed) as usize;
    let n = vfs::write(slot, off, bytes);
    if n != bytes.len() {
        return EPERM;
    }
    entry.off.store(off + n, Ordering::Relaxed);
    n as i64
}

fn sys_stat(fd: u64, out: u64, len: u64) -> i64 {
    let Some(index) = find_fd(fd, current_pid()) else {
        return EINVAL;
    };
    if len < vfs::STAT_LEN as u64 || len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    if let Err(e) = userptr::validate(out, len as usize) {
        return e;
    }
    let slot = FILES[index].vslot.load(Ordering::Relaxed) as usize;
    // SAFETY: `userptr::validate` proved the whole `out..out+len` range is
    // inside one registered user VMA; single-core IF=0 dispatch means no
    // aliasing writer. The slice is dropped before this call returns.
    let dst = unsafe { core::slice::from_raw_parts_mut(out as *mut u8, len as usize) };
    if !vfs::encode_stat(slot, dst) {
        return EINVAL;
    }
    vfs::STAT_LEN as i64
}

fn sys_readdir(fd: u64, out: u64, len: u64) -> i64 {
    let Some(index) = find_fd(fd, current_pid()) else {
        return EINVAL;
    };
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    if let Err(e) = userptr::validate(out, len as usize) {
        return e;
    }
    // Bounded staging buffer: at most MAX_FILES directory records, so a
    // hostile user length cannot inflate kernel work or allocate memory.
    let mut staged = [0u8; vfs::MAX_FILES * vfs::DIRENT_LEN];
    let cap = (len as usize).min(staged.len());
    let slot = FILES[index].vslot.load(Ordering::Relaxed) as usize;
    let n = match vfs::readdir(slot, &mut staged[..cap]) {
        Ok(n) => n,
        Err(e) => return e,
    };
    // SAFETY: same single-core, IF=0, one-registered-VMA contract as
    // `sys_stat`; `n <= cap <= len`, so the destination is in range.
    let dst = unsafe { core::slice::from_raw_parts_mut(out as *mut u8, n) };
    dst.copy_from_slice(&staged[..n]);
    n as i64
}

/// Dispatch one hito-4 syscall number. `None` means "not mine", so the
/// caller can keep its existing `ENOSYS` fallthrough unchanged.
pub fn dispatch_fs(nr: u64, args: [u64; 6]) -> Option<i64> {
    let ret = match nr {
        NR_OPEN => sys_open(args[0], args[1], args[2]),
        NR_CLOSE => sys_close(args[0]),
        NR_READ => sys_read(args[0], args[1], args[2]),
        NR_WRITE => sys_write(args[0], args[1], args[2]),
        NR_STAT => sys_stat(args[0], args[1], args[2]),
        NR_READDIR => sys_readdir(args[0], args[1], args[2]),
        _ => return None,
    };
    Some(ret)
}

/// Close every descriptor a terminated process still owns. The
/// integrator can call this from its `Exit` path; without it the table
/// simply keeps a tombstoned PID's entries, which no other PID can use.
pub fn release_pid(pid: u32) {
    for (i, entry) in FILES.iter().enumerate() {
        if entry.pid.load(Ordering::Relaxed) == pid && entry.used.load(Ordering::Relaxed) != 0 {
            entry.used.store(0, Ordering::Relaxed);
            let _ = i;
        }
    }
}
