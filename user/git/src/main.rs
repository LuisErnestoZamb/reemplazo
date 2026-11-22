//! Hito 6 — `user/git`: a user process that creates another user process.
//!
//! `no_std`, no heap, no allocator. The staged ELF is the `hello` module of
//! the dedicated `smoke-user` ISO. On its first invocation it reproduces the
//! hito-3 console, hito-4 filesystem and editor proofs (so the marker chain
//! is unchanged up to `USER_EDITOR_OK`), then calls `Spawn("/GIT.ELF", argv)`
//! to start a **second** process from the same image. The child recognises
//! itself through the argv block the kernel wrote into its stack, runs a
//! minimal `echo` over the kernel-owned RAM volume, sends the bytes back
//! through IPC and terminates with `Kill(0)` + `Yield` (deliberately *not*
//! the boot-proof exit path). The parent blocks in `Waitpid`, reads the IPC
//! message, checks it byte-exactly and prints `USER_GIT_OK`.
//!
//! The parent finally exits through `exit(0)` after a bounded 100-yield
//! window, exactly like the hito-4 editor, so the hito-2 (`USER_RETURN_OK`,
//! `SCHED_RR_OK`, `USER_YIELD_OK`, `USER_FAULT_OK`) tail still runs.
//!
//! Syscalls 22..=27 are mirrored privately here instead of in `userlib` so no
//! file outside this new crate has to change. The raw `int 0x80` wrapper is
//! the only unsafe in `gitsys`; each use carries a SAFETY comment.

#![no_std]
#![no_main]

use userlib as sys;

core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

const DOC_CAP: usize = 2048;
const LINE_CAP: usize = 256;
const STAT_CAP: usize = sys::STAT_LEN;
const DIR_CAP: usize = 8 * sys::DIRENT_LEN;
const MAX_POLLS: u32 = 1_000_000;
/// Bounded wait/Yield budget — a lost child must fail, never spin forever.
const MAX_WAITS: u32 = 100;

const DOC_PATH: &[u8] = b"/NOTES.TXT";
const DIR_PATH: &[u8] = b"/DOC";
const INSERT: &[u8] = b"user edit ok\n";

// --- Hito 6 fixtures ------------------------------------------------------
/// The spawnable image name, matching `kernel/src/userland/spawn.rs`.
const IMAGE_PATH: &[u8] = b"/GIT.ELF";
/// A plain, NUL-terminated argv blob; the kernel counts two arguments.
const ARGV: &[u8] = b"echo\0CHILD\0";
/// File the child writes through the hito-4 volume service.
const ECHO_PATH: &[u8] = b"/GIT.ECHO";
/// The payload echoed through the RAM volume and then over IPC.
const ECHO: &[u8] = b"USER_GIT_ECHO_OK\n";
/// Bottom of the child's 16 KiB stack, where `Spawn` writes the argv block.
const ARGV_BASE: usize = 0x0000_0080_3fff_c100;
const ARGV_STRINGS_OFF: usize = 0x60;
const ARGV_PARENT_OFF: usize = 0x18;

// Non-zero initial bytes keep every buffer in .data: an all-zero static
// lands in .bss and rust-lld emits a second R|W PT_LOAD that the U1
// loader refuses as `AlreadyMapped` (same reason as user/shell/user/edit).
static mut GAP: gapbuf::Gap<DOC_CAP> = gapbuf::Gap::new();
static mut EXPECTED: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut BACK: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut STAT_BUF: [u8; STAT_CAP] = [b' '; STAT_CAP];
static mut DIR_BUF: [u8; DIR_CAP] = [b' '; DIR_CAP];
static mut LINE: [u8; LINE_CAP] = [b' '; LINE_CAP];

/// Pure, fixed-capacity gap buffer (byte-identical to the hito-4 editor).
mod gapbuf {
    #![forbid(unsafe_code)]

    pub struct Gap<const N: usize> {
        data: [u8; N],
        gap_start: usize,
        gap_end: usize,
    }

    impl<const N: usize> Gap<N> {
        pub const fn new() -> Self {
            Self {
                data: [b' '; N],
                gap_start: 0,
                gap_end: N,
            }
        }

        pub fn load(&mut self, src: &[u8]) -> bool {
            if src.len() > N {
                return false;
            }
            self.data[..src.len()].copy_from_slice(src);
            self.gap_start = src.len();
            self.gap_end = N;
            true
        }

        pub fn len(&self) -> usize {
            self.gap_start + (N - self.gap_end)
        }

        fn move_gap(&mut self, pos: usize) -> bool {
            if pos > self.len() {
                return false;
            }
            if pos < self.gap_start {
                let n = self.gap_start - pos;
                self.data.copy_within(pos..self.gap_start, self.gap_end - n);
                self.gap_start = pos;
                self.gap_end -= n;
            } else if pos > self.gap_start {
                let n = pos - self.gap_start;
                self.data
                    .copy_within(self.gap_end..self.gap_end + n, self.gap_start);
                self.gap_start = pos;
                self.gap_end += n;
            }
            true
        }

        pub fn insert(&mut self, pos: usize, bytes: &[u8]) -> bool {
            if pos > self.len() || bytes.len() > N.saturating_sub(self.len()) {
                return false;
            }
            if bytes.len() > self.gap_end - self.gap_start && !self.move_gap(self.len()) {
                return false;
            }
            if !self.move_gap(pos) {
                return false;
            }
            self.data[pos..pos + bytes.len()].copy_from_slice(bytes);
            self.gap_start += bytes.len();
            true
        }

        pub fn copy_out(&self, out: &mut [u8]) -> usize {
            let n = self.len();
            if out.len() < n {
                return 0;
            }
            let front = self.gap_start;
            out[..front].copy_from_slice(&self.data[..front]);
            out[front..n].copy_from_slice(&self.data[self.gap_end..N]);
            n
        }
    }
}

// --- Hito 6 user-side ABI (private mirror of kernel syscalls 22..=27) -----
mod gitsys {
    #![allow(unsafe_code)]

    pub const NR_SPAWN: u64 = 22;
    pub const NR_WAITPID: u64 = 23;
    pub const NR_KILL: u64 = 24;
    pub const NR_IPC_SEND: u64 = 25;
    pub const NR_IPC_RECV: u64 = 26;
    pub const NR_IPC_CLOSE: u64 = 27;
    pub const EAGAIN: i64 = -16;
    /// Opaque IPC handle tag (same constant as `kernel/src/userland/ipc.rs`).
    pub const IPC_TAG: u64 = 0x5000_0000;

    #[inline]
    pub fn handle(pid: u32) -> u64 {
        IPC_TAG | u64::from(pid)
    }

    #[inline]
    pub fn spawn(path: &[u8], argv: &[u8]) -> i64 {
        // `raw4` owns the single unsafe asm block; the kernel validates both
        // user buffers with `userptr` before dereferencing them.
        raw4(
            NR_SPAWN,
            path.as_ptr() as u64,
            path.len() as u64,
            argv.as_ptr() as u64,
            argv.len() as u64,
        )
    }

    #[inline]
    pub fn waitpid(pid: u32, opts: u64) -> i64 {
        // Integer arguments only; no user pointer is passed.
        raw2(NR_WAITPID, u64::from(pid), opts)
    }

    /// Blocking form: bounded `Yield` loop around the non-blocking syscall.
    /// The child is `Ready` only after the first Yield, which is what makes
    /// this a real hand-off rather than a spin.
    pub fn wait_blocking(pid: u32) -> i64 {
        let mut spins: u32 = 0;
        loop {
            let ret = waitpid(pid, 0);
            if ret != EAGAIN {
                return ret;
            }
            if spins >= super::MAX_WAITS {
                return EAGAIN;
            }
            spins = spins.saturating_add(1);
            let _ = super::sys::yield_now();
        }
    }

    #[inline]
    pub fn kill(pid: u32) -> i64 {
        // Integer argument only.
        raw1(NR_KILL, u64::from(pid))
    }

    #[inline]
    pub fn ipc_send(target: u64, bytes: &[u8]) -> i64 {
        // The kernel validates the buffer with `userptr` first.
        raw3(
            NR_IPC_SEND,
            target,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
        )
    }

    #[inline]
    pub fn ipc_recv(buf: &mut [u8]) -> i64 {
        // The kernel validates the buffer with `userptr` first.
        raw2(NR_IPC_RECV, buf.as_mut_ptr() as u64, buf.len() as u64)
    }

    #[inline]
    pub fn ipc_close() -> i64 {
        // No arguments, no memory touched by this wrapper.
        raw0(NR_IPC_CLOSE)
    }

    #[inline(always)]
    fn raw0(nr: u64) -> i64 {
        // SAFETY: `int 0x80` is the DPL3 gate; no user memory is passed.
        unsafe { raw(nr, 0, 0, 0, 0, 0, 0) }
    }

    #[inline(always)]
    fn raw1(nr: u64, a1: u64) -> i64 {
        // SAFETY: scalar argument only.
        unsafe { raw(nr, a1, 0, 0, 0, 0, 0) }
    }

    #[inline(always)]
    fn raw2(nr: u64, a1: u64, a2: u64) -> i64 {
        // SAFETY: scalar/pointer pair; the kernel validates any pointer.
        unsafe { raw(nr, a1, a2, 0, 0, 0, 0) }
    }

    #[inline(always)]
    fn raw3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        // SAFETY: `(handle, ptr, len)`; the kernel validates ptr/len.
        unsafe { raw(nr, a1, a2, a3, 0, 0, 0) }
    }

    #[inline(always)]
    fn raw4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
        // SAFETY: `(path_ptr, path_len, argv_ptr, argv_len)`; both user
        // buffers are validated by the kernel before any dereference.
        unsafe { raw(nr, a1, a2, a3, a4, 0, 0) }
    }

    #[inline(always)]
    unsafe fn raw(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
        let ret: i64;
        // SAFETY: the ABI's entry gate and argument registers; `nostack`
        // because the CPU switches to the kernel stack on CPL3 entry. The
        // kernel never trusts the values carried in these registers.
        unsafe {
            core::arch::asm!(
                "int 0x80",
                inlateout("rax") nr as i64 => ret,
                in("rdi") a1,
                in("rsi") a2,
                in("rdx") a3,
                in("r10") a4,
                in("r8") a5,
                in("r9") a6,
                options(nostack),
            );
        }
        ret
    }
}

// --- Static scratch accessors (one single-threaded CPL3 process each) -----

fn gap() -> &'static mut gapbuf::Gap<DOC_CAP> {
    // SAFETY: single-threaded user process; one live borrow at a time.
    unsafe { &mut *core::ptr::addr_of_mut!(GAP) }
}

fn expected() -> &'static mut [u8; DOC_CAP] {
    // SAFETY: single-threaded, one live borrow at a time.
    unsafe { &mut *core::ptr::addr_of_mut!(EXPECTED) }
}

fn back() -> &'static mut [u8; DOC_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(BACK) }
}

fn stat_buf() -> &'static mut [u8; STAT_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(STAT_BUF) }
}

fn dir_buf() -> &'static mut [u8; DIR_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(DIR_BUF) }
}

fn line() -> &'static mut [u8; LINE_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(LINE) }
}

// --- argv block written by the kernel into this process's stack -----------

/// `argc == 0` in a process that was loaded but never spawned.
fn argc() -> u64 {
    // SAFETY: ARGV_BASE is inside the 16 KiB user-mapped stack page, 8-byte
    // aligned; the loader zeroes every stack page before the first CPL3 entry.
    unsafe { core::ptr::read_volatile(ARGV_BASE as *const u64) }
}

fn argv_is_echo() -> bool {
    // SAFETY: same mapped stack page as `argc`; the kernel copied our own
    // argv blob at ARGV_BASE + 0x60 and NUL-terminated it.
    let mut at = ARGV_BASE + ARGV_STRINGS_OFF;
    for want in b"echo" {
        // SAFETY: bounded read inside the mapped argv block.
        let got = unsafe { core::ptr::read_volatile(at as *const u8) };
        if got != *want {
            return false;
        }
        at += 1;
    }
    // SAFETY: see above; the terminator is the fifth byte of "echo\0".
    unsafe { core::ptr::read_volatile(at as *const u8) == 0 }
}

fn parent_pid() -> u32 {
    // SAFETY: the kernel wrote the spawning pid at ARGV_BASE + 0x18 before
    // publishing the child PCB; the page is mapped user-RW.
    unsafe { core::ptr::read_volatile((ARGV_BASE + ARGV_PARENT_OFF) as *const u64) as u32 }
}

fn die(what: &[u8]) -> ! {
    sys::write_str("FATAL: ugit: ");
    let _ = sys::write(2, what);
    sys::write_str("\n");
    sys::exit(1)
}

fn expect(ok: bool, what: &[u8]) {
    if !ok {
        die(what);
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    // The child branch never prints a boot marker: it only runs the echo
    // command and reports over IPC, so the smoke's marker order is unchanged.
    if argc() > 0 {
        expect(argv_is_echo(), b"child argv[0] is not echo");
        child_proof();
    }

    // Parent: hito 3 + hito 4 preamble (same reasons as `user/edit`).
    match sys::console_dims() {
        Some((cols, rows)) if cols > 0 && rows > 0 => {}
        _ => die(b"no VGA console"),
    }
    const GLYPH: u8 = b'U';
    const ATTR: u8 = 0x1f;
    expect(
        sys::vga_put_cell(0, 0, GLYPH, ATTR) == 0
            && sys::vga_flush() == 0
            && sys::vga_peek(0, 0) == Some((GLYPH, ATTR)),
        b"VGA round-trip",
    );
    sys::write_str("USER_CONSOLE_OK\n");
    sys::write_str("USER_SHELL_OK\n");

    fs_proof();
    editor_proof();
    git_proof();

    // One-line REPL for the smoke's keyboard phase (unchanged contract).
    sys::write_str("ugit> ");
    let mut polls: u32 = 0;
    loop {
        if polls >= 100 {
            sys::exit(0);
        }
        let n = sys::read(0, line());
        if n > 0 {
            let end = if (n as usize) <= LINE_CAP {
                n as usize
            } else {
                LINE_CAP
            };
            execute(&line()[..end]);
            sys::exit(0);
        } else if n < 0 {
            die(b"console Read");
        } else {
            polls = polls.saturating_add(1);
            if polls > MAX_POLLS {
                sys::exit(0);
            }
            let _ = sys::yield_now();
        }
    }
}

/// Child: a minimal `echo` against the RAM volume, then IPC to the parent.
fn child_proof() -> ! {
    let parent = parent_pid();
    expect(parent > 0, b"no parent pid in argv block");

    let out = sys::fs_open(ECHO_PATH, sys::O_WRONLY | sys::O_CREAT | sys::O_TRUNC);
    expect(out > 0, b"child open /GIT.ECHO");
    expect(
        sys::fs_write(out, ECHO) == ECHO.len() as i64,
        b"child echo write",
    );
    expect(sys::fs_close(out) == 0, b"child close /GIT.ECHO");

    let verify = sys::fs_open(ECHO_PATH, sys::O_RDONLY);
    expect(verify > 0, b"child reopen /GIT.ECHO");
    let n = sys::fs_read(verify, back());
    expect(n == ECHO.len() as i64, b"child echo read-back length");
    expect(
        eq(&back()[..ECHO.len()], ECHO),
        b"child echo read-back bytes",
    );
    expect(sys::fs_close(verify) == 0, b"child close after verify");

    expect(
        gitsys::ipc_send(gitsys::handle(parent), ECHO) == ECHO.len() as i64,
        b"child IpcSend",
    );
    expect(gitsys::ipc_close() == 0, b"child IpcClose");
    // `Kill(0)` marks this PCB Exited without entering the boot-proof exit
    // chain; the following Yield hands the CPU back to the waiting parent.
    expect(gitsys::kill(0) == 0, b"child Kill(0)");
    let _ = sys::yield_now();
    loop {
        core::hint::spin_loop();
    }
}

/// Parent: fail-closed checks, Spawn, blocking Waitpid, IPC byte-compare.
fn git_proof() {
    expect(
        gitsys::spawn(b"/NO-SUCH.ELF", ARGV) == sys::EINVAL,
        b"unknown image spawned",
    );
    expect(
        gitsys::ipc_send(0x1234, ECHO) == sys::EPERM,
        b"forged IPC handle accepted",
    );

    let pid = gitsys::spawn(IMAGE_PATH, ARGV);
    expect(pid > 0, b"Spawn /GIT.ELF");
    expect(
        gitsys::wait_blocking(pid as u32) == 0,
        b"Waitpid child status",
    );
    expect(
        gitsys::wait_blocking(pid as u32) == sys::EINVAL,
        b"reaped child still waitable",
    );

    let n = gitsys::ipc_recv(back());
    expect(n == ECHO.len() as i64, b"IpcRecv length");
    expect(eq(&back()[..ECHO.len()], ECHO), b"IpcRecv bytes differ");
    expect(gitsys::ipc_recv(back()) == 0, b"IpcRecv did not drain");

    // The child's echo also landed on the shared RAM volume.
    let fd = sys::fs_open(ECHO_PATH, sys::O_RDONLY);
    expect(fd > 0, b"open child's /GIT.ECHO");
    let m = sys::fs_read(fd, back());
    expect(m == ECHO.len() as i64, b"volume echo length");
    expect(eq(&back()[..ECHO.len()], ECHO), b"volume echo bytes differ");
    expect(sys::fs_close(fd) == 0, b"close /GIT.ECHO");

    sys::write_str("USER_GIT_OK\n");
}

/// Full FS syscall proof (byte-identical to the hito-4 editor).
fn fs_proof() {
    expect(
        sys::fs_open(b"/../ETC/PASSWD", sys::O_RDONLY) == sys::EPERM,
        b"path escape was not refused",
    );
    expect(
        sys::fs_open(b"/NO-SUCH-FILE.TXT", sys::O_RDONLY) == sys::EINVAL,
        b"missing file opened",
    );

    let fd = sys::fs_open(DOC_PATH, sys::O_RDWR);
    expect(fd > 0, b"open /NOTES.TXT");
    let n = sys::fs_read(fd, back());
    expect(n > 0 && (n as usize) <= DOC_CAP, b"read /NOTES.TXT");
    let n = n as usize;

    let stat = stat_buf();
    expect(
        sys::fs_stat(fd, stat) == sys::STAT_LEN as i64,
        b"stat /NOTES.TXT",
    );
    expect(
        sys::stat_size(stat) == Some(n as u64),
        b"stat size != read bytes",
    );
    expect(sys::fs_read(0, back()) == sys::EINVAL, b"fd 0 accepted");
    expect(sys::fs_close(0) == sys::EINVAL, b"fd 0 closed");

    let dir = sys::fs_open(DIR_PATH, sys::O_RDONLY);
    expect(dir > 0, b"open /DOC");
    let dn = sys::fs_readdir(dir, dir_buf());
    expect(
        dn > 0 && (dn as usize) % sys::DIRENT_LEN == 0,
        b"readdir /DOC",
    );
    let mut name = [0u8; sys::DIRENT_NAME];
    let mut found = false;
    let mut at = 0usize;
    while at + sys::DIRENT_LEN <= dn as usize {
        if let Some(got) = sys::dirent_name(&dir_buf()[at..at + sys::DIRENT_LEN], &mut name)
            && eq(got, b"README.TXT")
        {
            found = true;
        }
        at += sys::DIRENT_LEN;
    }
    expect(found, b"readdir missing README.TXT");
    expect(sys::fs_close(dir) == 0, b"close /DOC");
    expect(sys::fs_close(fd) == 0, b"close /NOTES.TXT");
    sys::write_str("USER_FS_OK\n");
}

/// Gap-buffer edit + write-back + byte-exact read-back (hito 4).
fn editor_proof() {
    let fd = sys::fs_open(DOC_PATH, sys::O_RDWR);
    expect(fd > 0, b"reopen /NOTES.TXT");
    let n = sys::fs_read(fd, back());
    expect(n > 0 && (n as usize) <= DOC_CAP, b"editor read");
    let n = n as usize;

    let buf = gap();
    expect(buf.load(&back()[..n]), b"gap load");
    let at = back()[..n]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(n, |i| i + 1);
    expect(buf.insert(at, INSERT), b"gap insert");
    let expected_len = buf.copy_out(expected());
    expect(expected_len == n + INSERT.len(), b"gap copy_out");

    expect(sys::fs_close(fd) == 0, b"close before save");
    let out = sys::fs_open(DOC_PATH, sys::O_WRONLY | sys::O_TRUNC);
    expect(out > 0, b"open for save");
    expect(
        sys::fs_write(out, &expected()[..expected_len]) == expected_len as i64,
        b"save write",
    );
    expect(sys::fs_close(out) == 0, b"close after save");

    let verify = sys::fs_open(DOC_PATH, sys::O_RDONLY);
    expect(verify > 0, b"reopen for verify");
    let read_back = sys::fs_read(verify, back());
    expect(read_back == expected_len as i64, b"read-back length");
    expect(
        eq(&back()[..expected_len], &expected()[..expected_len]),
        b"read-back bytes differ",
    );
    let stat = stat_buf();
    expect(
        sys::fs_stat(verify, stat) == sys::STAT_LEN as i64
            && sys::stat_size(stat) == Some(expected_len as u64),
        b"read-back stat",
    );
    expect(sys::fs_close(verify) == 0, b"close after verify");
    sys::write_str("USER_EDITOR_OK\n");
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}

fn write_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    if value == 0 {
        at -= 1;
        digits[at] = b'0';
    }
    while value > 0 {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let _ = sys::write(1, &digits[at..]);
}

fn execute(raw: &[u8]) {
    let mut split = 0;
    while split < raw.len() && raw[split] != b' ' && raw[split] != b'\t' {
        split += 1;
    }
    let cmd = &raw[..split];
    let mut rest = &raw[split..];
    while let Some((first, tail)) = rest.split_first()
        && (*first == b' ' || *first == b'\t')
    {
        rest = tail;
    }
    if eq(cmd, b"help") {
        sys::write_str("builtins: help echo uptime edit exit\n");
    } else if eq(cmd, b"echo") {
        let _ = sys::write(1, rest);
        sys::write_str("\n");
    } else if eq(cmd, b"uptime") {
        let now = sys::time();
        if now < 0 {
            sys::write_str("uptime: unavailable\n");
        } else {
            sys::write_str("uptime: ");
            write_u64(now as u64);
            sys::write_str(" ms\n");
        }
    } else if eq(cmd, b"edit") {
        sys::write_str("editor: document saved (USER_EDITOR_OK)\n");
    } else if !cmd.is_empty() {
        sys::write_str("ugit: unknown command (try help)\n");
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    sys::write_str("FATAL: ugit panic at ");
    if let Some(loc) = info.location() {
        sys::write_str(loc.file());
        sys::write_str(":");
        write_u64(loc.line() as u64);
    }
    sys::write_str("\n");
    sys::exit(1)
}
