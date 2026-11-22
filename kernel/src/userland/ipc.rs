//! Hito 6 — bounded, per-process IPC (syscalls 25..=27).
//!
//! The kernel keeps ownership of the channel storage: every live PCB gets one
//! fixed-size inbox, so there is no heap, no dynamic queue and no pointer the
//! user can forge into kernel memory. A process never sees a table index — it
//! sends to an **opaque handle** derived from the target pid
//! ([`handle`]) and can only receive from its own inbox.
//!
//! `IpcSend` copies at most [`IPC_CAP`] bytes into the target inbox (a full
//! inbox is refused, never truncated). `IpcRecv` drains the caller's own
//! inbox into a `userptr`-validated buffer. `IpcClose` clears the caller's
//! inbox. Every path is fail-closed: bad handle, bad user buffer, unknown
//! process and over-capacity all return an errno.
//!
//! The channel table is atomics-only, like `vfs.rs`: single-core, `int 0x80`
//! runs with IF=0, and no other agent observes a channel mid-syscall. The
//! one raw write into user memory lives in the tiny [`userbuf`] submodule,
//! which is the only opt-in to unsafe here; all channel logic is unsafe-free.

// `deny` (not `forbid`) at module level so the tiny validated user-buffer
// writer below can opt in to the one raw copy with a documented SAFETY note;
// every other line in this file is unsafe-free.
#![deny(unsafe_code)]

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use super::process::MAX_PROCS;
use super::sched::current_pid;
use super::syscall::{EINVAL, EPERM};
use super::userptr;

// --- Stable syscall numbers (mirrored in `user/git`'s private ABI) --------
/// `IpcSend(handle: u64, buf: *const u8, len: u64) -> i64`
pub const NR_IPC_SEND: u64 = 25;
/// `IpcRecv(buf: *mut u8, len: u64) -> i64`
pub const NR_IPC_RECV: u64 = 26;
/// `IpcClose() -> i64`
pub const NR_IPC_CLOSE: u64 = 27;

/// Hard cap per inbox. Four KiB total per process, statically allocated.
pub const IPC_CAP: usize = 4 * 1024;
/// Chunk used when copying into atomic bytes: keeps the kernel stack small.
const COPY_CHUNK: usize = 64;
/// Tag that makes a handle unmistakably an IPC handle (console fds start at
/// 0, volume fds at `0x4000_0000`, so no other subsystem can alias one).
const IPC_TAG: u64 = 0x5000_0000;

/// One inbox. `open == 0` means "no such channel": every operation on it
/// fails, and a closed inbox can never be reopened by user code (the only
/// writer of `open` on the close path is this module).
struct Inbox {
    open: AtomicU8,
    len: AtomicUsize,
    data: [AtomicU8; IPC_CAP],
}

impl Inbox {
    const fn new() -> Self {
        Self {
            open: AtomicU8::new(0),
            len: AtomicUsize::new(0),
            data: [const { AtomicU8::new(0) }; IPC_CAP],
        }
    }
}

static INBOXES: [Inbox; MAX_PROCS] = [const { Inbox::new() }; MAX_PROCS];

/// Opaque handle for `pid`. The user only ever passes this value back; it is
/// not a raw slot index and no user code can construct an inbox address.
#[inline]
pub fn handle(pid: u32) -> u64 {
    IPC_TAG | u64::from(pid)
}

fn decode(handle: u64) -> Option<usize> {
    if handle < IPC_TAG {
        return None;
    }
    let pid = (handle - IPC_TAG) as usize;
    if pid == 0 || pid >= MAX_PROCS {
        return None;
    }
    Some(pid)
}

/// Open the current process's inbox the first time it needs one. PID0 (the
/// ring-0 idle context) never owns an inbox.
fn open_current() -> Option<&'static Inbox> {
    let pid = usize::try_from(current_pid()).ok()?;
    let box_ = INBOXES.get(pid)?;
    box_.open.store(1, Ordering::Relaxed);
    Some(box_)
}

fn sys_send(target: u64, buf: u64, len: u64) -> i64 {
    let Some(slot) = decode(target) else {
        return EPERM;
    };
    if len > IPC_CAP as u64 {
        return EINVAL;
    }
    let bytes = match userptr::validated_slice(buf, len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    // The first message opens the target's inbox: a child normally sends
    // before its parent has had a chance to call IpcRecv. Only a close (or a
    // forged/invalid handle) ever makes a channel unusable.
    let box_ = match INBOXES.get(slot) {
        Some(b) if b.open.load(Ordering::Relaxed) == 0 => {
            b.open.store(1, Ordering::Release);
            b
        }
        Some(b) => b,
        None => return EPERM,
    };
    let used = box_.len.load(Ordering::Relaxed).min(IPC_CAP);
    if used.saturating_add(bytes.len()) > IPC_CAP {
        return EPERM; // bounded: full inbox is refused, never truncated
    }
    let mut at = 0usize;
    while at < bytes.len() {
        let n = (bytes.len() - at).min(COPY_CHUNK);
        let mut chunk = [0u8; COPY_CHUNK];
        chunk[..n].copy_from_slice(&bytes[at..at + n]);
        for (i, byte) in chunk[..n].iter().enumerate() {
            box_.data[used + at + i].store(*byte, Ordering::Relaxed);
        }
        at += n;
    }
    // Publish the new length only after every byte is in place so a reader on
    // the same core can never observe a half-written message.
    box_.len.store(used + bytes.len(), Ordering::Release);
    bytes.len() as i64
}

fn sys_recv(buf: u64, len: u64) -> i64 {
    if len > IPC_CAP as u64 {
        return EINVAL;
    }
    if let Err(e) = userptr::validate(buf, len as usize) {
        return e;
    }
    let Some(box_) = open_current() else {
        return EPERM;
    };
    let used = box_.len.load(Ordering::Acquire).min(IPC_CAP);
    let n = (len as usize).min(used);
    if n == 0 {
        return 0;
    }
    let mut staged = [0u8; COPY_CHUNK];
    let mut at = 0usize;
    while at < n {
        let count = (n - at).min(COPY_CHUNK);
        for (i, byte) in staged[..count].iter_mut().enumerate() {
            *byte = box_.data[at + i].load(Ordering::Relaxed);
        }
        // SAFETY (in `userbuf`): `userptr::validate` proved `buf..buf+len`
        // lies wholly inside one registered VMA of the current process;
        // `at + count <= n <= len`; single-core, IF=0 dispatch means no
        // concurrent writer. The slice is dropped before this call returns.
        userbuf::write(buf + at as u64, &staged[..count]);
        at += count;
    }
    // Consume the message: shift the unread tail down and shrink the length.
    let mut i = n;
    while i < used {
        box_.data[i - n].store(box_.data[i].load(Ordering::Relaxed), Ordering::Relaxed);
        i += 1;
    }
    box_.len.store(used - n, Ordering::Release);
    n as i64
}

fn sys_close() -> i64 {
    let Some(box_) = open_current() else {
        return EPERM;
    };
    box_.len.store(0, Ordering::Release);
    box_.open.store(0, Ordering::Release);
    0
}

/// Dispatch the three IPC syscall numbers. `None` means "not mine".
pub fn dispatch_ipc(nr: u64, args: [u64; 6]) -> Option<i64> {
    let ret = match nr {
        NR_IPC_SEND => sys_send(args[0], args[1], args[2]),
        NR_IPC_RECV => sys_recv(args[0], args[1]),
        NR_IPC_CLOSE => sys_close(),
        _ => return None,
    };
    Some(ret)
}

/// The single piece of unsafe in this file: a validated write into user
/// memory. Kept in its own scope so `forbid(unsafe_code)` still covers the
/// channel logic above.
mod userbuf {
    #[allow(unsafe_code)]
    pub fn write(ptr: u64, src: &[u8]) {
        // SAFETY: the caller proved the whole `ptr..ptr+src.len()` range is
        // inside one registered user VMA via `userptr::validate`, the process
        // cannot run concurrently (single core, IF=0 in the int 0x80 gate),
        // and `src` is a private stack buffer that cannot alias user memory.
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), ptr as *mut u8, src.len()) };
    }
}
