//! Hito 6 — process creation, `waitpid`/`kill` and the hito-6 dispatch chain
//! (syscalls 22..=27: Spawn, Waitpid, Kill, IpcSend, IpcRecv, IpcClose).
//!
//! `Spawn(path, argv)` resolves `path` against the user volume's executable
//! registry, reuses the hito-1 ELF loader ([`super::load::load`], which parses
//! through `elf::parse`), writes the caller's `argv` into the child's own
//! stack page and creates a fresh PCB with `sched::spawn_with_stack`. The
//! child starts `Ready`, so the caller decides when it runs by yielding —
//! there is no implicit context switch inside a syscall.
//!
//! `Waitpid(pid, opts)` is a bounded poll: it returns `EAGAIN` while the child
//! is alive, and the `user/git` wrapper loops with `Yield` until the child
//! terminates. `Kill(0)` marks the caller `Exited` **without** taking the
//! boot-proof exit path (`sched::exit_current`), so a short-lived child can
//! hand control back to its parent with one `Yield` instead of triggering the
//! hito-2 proof chain that ends the smoke.
//!
//! The integrator only has to chain one call into `syscall.rs`'s default arm:
//!
//! ```text
//! .or_else(|| crate::userland::spawn::dispatch_spawn(
//!     n, [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]))
//! ```
//!
//! plus the two `mod` lines in `userland/mod.rs`. Everything here is
//! fail-closed: every user pointer goes through [`super::userptr`], paths go
//! through the volume's validator, handles are opaque and all counters are
//! compile-time bounded. No heap, no `unwrap`, no panicking arithmetic.

use core::sync::atomic::{AtomicI64, AtomicU8, AtomicU32, Ordering};

use super::process::MAX_PROCS;
use super::sched::{self, current_pid};
use super::syscall::{EFAULT, EINVAL, EPERM};
use super::userptr;
use super::vfs;
use crate::memory::{self, USER_END, USER_STACK_SIZE};

// --- Stable syscall numbers (mirrored in `user/git`'s private ABI) --------
/// `Spawn(path: *const u8, path_len: u64, argv: *const u8, argv_len: u64) -> pid`
pub const NR_SPAWN: u64 = 22;
/// `Waitpid(pid: u32, opts: u64) -> exit_code`
pub const NR_WAITPID: u64 = 23;
/// `Kill(pid: u32) -> i64` (`pid == 0` means self)
pub const NR_KILL: u64 = 24;

/// Poll again later. Deliberately outside the milestone-1 errno set so a
/// caller cannot mistake it for success; the `userlib`-style wrapper turns it
/// into a blocking loop with a hard yield budget.
pub const EAGAIN: i64 = -16;
/// Non-blocking `Waitpid`: return `0` instead of [`EAGAIN`].
pub const WNOHANG: u64 = 1;

/// The only executable the smoke's user volume carries. The ISO stages the
/// `user/git` ELF as the `hello` multiboot module, which is the single image
/// the U1 loader captures — spawning again with the same image is what makes
/// parent and child share one code base while keeping separate PCBs/CR3s.
pub const GIT_IMAGE: &[u8] = b"/GIT.ELF";

/// Bottom-of-stack address where the child's argv block is written. The
/// loader maps 16 KiB of zeroed RW pages at `USER_END - USER_STACK_SIZE`, so
/// this is a real, user-accessible address in the child's own address space
/// (and reads as `argc == 0` in the parent, which has never been spawned).
pub const ARGV_BASE: u64 = USER_END - USER_STACK_SIZE + 0x100;
/// Where the NUL-separated argv strings begin inside that block.
const ARGV_STRINGS_OFF: u64 = 0x60;
/// Maximum bytes of argv strings we will copy (the whole block is 0x100 B).
const ARGV_STRINGS_CAP: usize = 160;
/// Bytes zeroed at `ARGV_BASE` before publishing the block.
const ARGV_BLOCK_LEN: usize = 0x100;
/// At most four arguments are representable in the block.
const MAX_ARGC: usize = 4;

/// One child record. `pid == 0` means free; the table is indexed by slot, not
/// by pid, so a stale pid can never alias another parent's child.
struct Child {
    pid: AtomicU32,
    parent: AtomicU32,
    state: AtomicU8,
    code: AtomicI64,
}

impl Child {
    const fn new() -> Self {
        Self {
            pid: AtomicU32::new(0),
            parent: AtomicU32::new(u32::MAX),
            state: AtomicU8::new(0),
            code: AtomicI64::new(0),
        }
    }
}

const CHILD_ALIVE: u8 = 1;
const CHILD_EXITED: u8 = 2;

static CHILDREN: [Child; MAX_PROCS] = [const { Child::new() }; MAX_PROCS];

fn free_slot() -> Option<usize> {
    CHILDREN
        .iter()
        .position(|c| c.pid.load(Ordering::Relaxed) == 0)
}

fn find_child(parent: u32, pid: u32) -> Option<&'static Child> {
    CHILDREN.iter().find(|c| {
        c.pid.load(Ordering::Relaxed) == pid
            && c.parent.load(Ordering::Relaxed) == parent
            && c.pid.load(Ordering::Relaxed) != 0
    })
}

/// Find a record by child pid alone (used when a child terminates itself and
/// does not know which slot it occupies).
fn find_by_pid(pid: u32) -> Option<&'static Child> {
    if pid == 0 {
        return None;
    }
    CHILDREN
        .iter()
        .find(|c| c.pid.load(Ordering::Relaxed) == pid)
}

/// Write `argc`, the first two argv pointers, the parent pid and the flat
/// NUL-separated strings into the child's bottom stack page. The caller must
/// have checked the blob is non-empty and NUL-terminated.
fn write_argv(space: &memory::UserPageTable, argv: &[u8], parent: u32) -> Result<(), i64> {
    if argv.is_empty() || argv.len() > ARGV_STRINGS_CAP || argv[argv.len() - 1] != 0 {
        return Err(EINVAL);
    }
    let argc = argv.iter().filter(|b| **b == 0).count().min(MAX_ARGC);
    let first_nul = argv.iter().position(|b| *b == 0).ok_or(EINVAL)?;
    let second_ptr = argv[first_nul + 1..]
        .iter()
        .position(|b| *b == 0)
        .map(|_| ARGV_BASE + ARGV_STRINGS_OFF + (first_nul + 1) as u64)
        .unwrap_or(0);

    let page = ARGV_BASE & !(memory::FRAME_SIZE - 1);
    let (frame, _) = memory::user_page_frame(space, page).ok_or(EFAULT)?;
    let base = (frame.start_phys() + (ARGV_BASE - page)) as *mut u8;
    // SAFETY: `user_page_frame` proved this virtual page is mapped user-RW in
    // the freshly built child table; `frame` is an exclusively owned 4 KiB
    // frame reachable through the kernel identity map, ARGV_BASE's 0x100-byte
    // block lies entirely inside it (offset 0x100 + 0x100 < 0x1000), and no
    // other agent can observe the child before `spawn_with_stack` publishes
    // it. Single core, IF=0 in the syscall gate.
    unsafe {
        core::ptr::write_bytes(base, 0, ARGV_BLOCK_LEN);
        core::ptr::write_unaligned(base as *mut u64, argc as u64);
        core::ptr::write_unaligned(base.add(8) as *mut u64, ARGV_BASE + ARGV_STRINGS_OFF);
        core::ptr::write_unaligned(base.add(16) as *mut u64, second_ptr);
        core::ptr::write_unaligned(base.add(24) as *mut u64, u64::from(parent));
        core::ptr::copy_nonoverlapping(
            argv.as_ptr(),
            base.add(ARGV_STRINGS_OFF as usize),
            argv.len(),
        );
    }
    Ok(())
}

fn sys_spawn(path_ptr: u64, path_len: u64, argv_ptr: u64, argv_len: u64) -> i64 {
    if path_len == 0 || path_len > vfs::MAX_PATH as u64 {
        return EINVAL;
    }
    let slot = match free_slot() {
        Some(i) => i,
        None => return EPERM, // child table full — never overwrite a live child
    };
    let path = match userptr::validated_slice(path_ptr, path_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if let Err(e) = vfs::validate_path(path) {
        return e;
    }
    // Only the registered executable is spawnable. An unknown path is a
    // lookup failure, not a silent fallback to whatever module was staged.
    if path.len() != GIT_IMAGE.len() || !path.iter().zip(GIT_IMAGE.iter()).all(|(a, b)| a == b) {
        return EINVAL;
    }
    let argv = match userptr::validated_slice(argv_ptr, argv_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let raw = match super::module::hello_bytes() {
        Some(bytes) => bytes,
        None => return EINVAL, // this boot carries no user executable
    };
    let proc = match super::load::load(raw) {
        Ok(p) => p,
        Err(_) => return EINVAL, // malformed ELF: fail closed
    };
    let parent = current_pid();
    if write_argv(&proc.space, argv, parent).is_err() {
        proc.destroy();
        return EFAULT;
    }
    let cr3 = proc.space.root.start_phys();
    let entry = proc.entry;
    let stack = proc.user_stack_top;
    let pid = match sched::spawn_with_stack(entry, cr3, stack) {
        Some(pid) => pid,
        None => {
            proc.destroy();
            return EPERM;
        }
    };
    // `LoadedProcess`/`UserPageTable` have no `Drop` implementation, so the
    // handle falling out of scope here deliberately leaves the child's frames
    // allocated: no milestone has a safe teardown point while its CR3 is live.

    let child = &CHILDREN[slot];
    child.pid.store(pid, Ordering::Relaxed);
    child.parent.store(parent, Ordering::Relaxed);
    child.code.store(0, Ordering::Relaxed);
    child.state.store(CHILD_ALIVE, Ordering::Release);
    pid as i64
}

fn sys_waitpid(pid: u32, opts: u64) -> i64 {
    let parent = current_pid();
    if pid == 0 {
        // Wait for any child of this process (lowest live pid wins).
        for child in CHILDREN.iter() {
            if child.parent.load(Ordering::Relaxed) == parent
                && child.state.load(Ordering::Acquire) == CHILD_EXITED
            {
                let code = child.code.load(Ordering::Relaxed);
                child.pid.store(0, Ordering::Release);
                return code;
            }
        }
        if opts & WNOHANG != 0 {
            return 0;
        }
        return EAGAIN;
    }
    let Some(child) = find_child(parent, pid) else {
        return EINVAL;
    };
    match child.state.load(Ordering::Acquire) {
        CHILD_EXITED => {
            let code = child.code.load(Ordering::Relaxed);
            child.pid.store(0, Ordering::Release);
            code
        }
        _ if opts & WNOHANG != 0 => 0,
        _ => EAGAIN,
    }
}

fn sys_kill(pid: u32) -> i64 {
    let me = current_pid();
    if pid == 0 || pid == me {
        if me == 0 {
            return EPERM; // PID0 is the ring-0 idle context, never killable
        }
        if let Some(child) = find_by_pid(me) {
            child.state.store(CHILD_EXITED, Ordering::Release);
        }
        let _ = sched::exit(me);
        return 0;
    }
    match find_child(me, pid) {
        Some(child) if child.state.load(Ordering::Acquire) == CHILD_ALIVE => {
            child.state.store(CHILD_EXITED, Ordering::Release);
            0
        }
        _ => EPERM,
    }
}

/// Dispatch the six hito-6 syscall numbers (22..=27). `None` means "not mine",
/// so the existing `ENOSYS` fallthrough stays byte-identical for every other
/// number. IPC numbers are delegated to [`super::ipc`] here so the integrator
/// only needs one `or_else` line in `syscall.rs`.
pub fn dispatch_spawn(nr: u64, args: [u64; 6]) -> Option<i64> {
    let ret = match nr {
        NR_SPAWN => sys_spawn(args[0], args[1], args[2], args[3]),
        NR_WAITPID => sys_waitpid(args[0] as u32, args[1]),
        NR_KILL => sys_kill(args[0] as u32),
        _ => return super::ipc::dispatch_ipc(nr, args),
    };
    Some(ret)
}
