//! Minimal `no_std` user-space syscall library — no libc, no dependencies
//! beyond `core`.
//!
//! Every call is a single `int 0x80` against the kernel's DPL3 IDT gate
//! (vector 128). SysV argument registers `rdi, rsi, rdx, r10, r8, r9` carry
//! up to six arguments; `rax` carries the number in and the i64 result out.
//! A negative result is an errno (see the `E*` constants).
//!
//! The kernel-side ABI and its pointer-validation rules live in
//! `docs/syscall-abi.md`. `user/hello/src/sys.rs` may inline the same raw
//! wrapper instead of depending on this crate — the numbers and errnos
//! below are the shared source of truth.

#![no_std]
// `forbid` cannot be scoped down, so we `deny` crate-wide and `allow` only
// inside `arch`, which holds the one `unsafe` asm wrapper (each use has a
// `// SAFETY:` comment). No other unsafe code exists in this crate.
#![deny(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

// --- Stable syscall numbers (mirror kernel/src/userland/syscall.rs) ------
pub const NR_WRITE: u64 = 0;
pub const NR_EXIT: u64 = 1;
pub const NR_YIELD: u64 = 2;
pub const NR_TIME: u64 = 3;
// Hito 3 — console + VGA service (mirrors kernel/src/userland/console.rs).
pub const NR_READ: u64 = 4;
pub const NR_VGA_DIMS: u64 = 5;
pub const NR_VGA_PUT_CELL: u64 = 6;
pub const NR_VGA_CLEAR: u64 = 7;
pub const NR_VGA_FLUSH: u64 = 8;
pub const NR_VGA_PEEK: u64 = 9;
// Hito 4 — filesystem service (mirrors kernel/src/userland/fs.rs).
pub const NR_OPEN: u64 = 10;
pub const NR_CLOSE: u64 = 11;
pub const NR_FS_READ: u64 = 12;
pub const NR_FS_WRITE: u64 = 13;
pub const NR_STAT: u64 = 14;
pub const NR_READDIR: u64 = 15;
// Hito 5 — network service (mirrors kernel/src/userland/net.rs).
pub const NR_DNS_RESOLVE: u64 = 16;
pub const NR_SOCK_CONNECT: u64 = 17;
pub const NR_SOCK_SEND: u64 = 18;
pub const NR_SOCK_RECV: u64 = 19;
pub const NR_SOCK_CLOSE: u64 = 20;
pub const NR_TLS_UPGRADE: u64 = 21;

// --- Hito 4: open flags and wire layouts ---------------------------------
/// Read-only access (the default).
pub const O_RDONLY: u64 = 0;
/// Write-only access.
pub const O_WRONLY: u64 = 1;
/// Read/write access.
pub const O_RDWR: u64 = 2;
/// Create the file when it does not exist.
pub const O_CREAT: u64 = 0x40;
/// Truncate an existing file on open.
pub const O_TRUNC: u64 = 0x200;
/// Start every write at end of file.
pub const O_APPEND: u64 = 0x400;

/// `Stat` record size: `size: u64 LE`, `kind: u8` (0 file / 1 dir),
/// `flags: u8`, six reserved bytes.
pub const STAT_LEN: usize = 16;
/// `Readdir` record size: `kind: u8`, `name_len: u8`, 62 name bytes.
pub const DIRENT_LEN: usize = 64;
/// Number of name bytes in one `Readdir` record.
pub const DIRENT_NAME: usize = DIRENT_LEN - 2;

// --- Errnos (mirror kernel/src/userland/syscall.rs) ----------------------
pub const EINVAL: i64 = -1;
pub const EFAULT: i64 = -2;
pub const EPERM: i64 = -13;
pub const ENOSYS: i64 = -38;
/// `SockRecv` had no data ready: call `yield_now` and retry (hito 5).
pub const EAGAIN: i64 = -11;

/// Write `s` to stdout (fd 1). Returns the byte count, or a negative errno.
#[inline]
pub fn write_str(s: &str) -> i64 {
    write(1, s.as_bytes())
}

/// Write `bytes` to `fd` (1 = stdout, 2 = stderr). Returns the byte count,
/// or a negative errno. The kernel refuses non-UTF-8 payloads today.
#[inline]
pub fn write(fd: u64, bytes: &[u8]) -> i64 {
    arch::syscall3(NR_WRITE, fd, bytes.as_ptr() as u64, bytes.len() as u64)
}

/// Terminate the current process. The kernel hook never returns; if no
/// scheduler is installed, the kernel prints and halts.
#[inline]
pub fn exit(code: i32) -> ! {
    let _ = arch::syscall1(NR_EXIT, code as u64);
    // Defensive: a buggy kernel must not hand control back into user code
    // after an `exit`. Spin (never `hlt` — IF may be clear in user mode).
    loop {
        core::hint::spin_loop();
    }
}

/// Cooperative yield (milestone 1: returns 0 immediately).
///
/// `yield` is a Rust keyword, so the canonical name is the raw identifier
/// `r#yield`; `yield_now` is a convenience alias.
#[inline]
pub fn r#yield() -> i64 {
    arch::syscall0(NR_YIELD)
}

/// Alias for [`r#yield`].
#[inline]
pub fn yield_now() -> i64 {
    r#yield()
}

/// Milliseconds since boot, or a negative errno.
#[inline]
pub fn time() -> i64 {
    arch::syscall0(NR_TIME)
}

// --- Hito 3: console + VGA service ---------------------------------------

/// Read one line from the console into `buf`. Returns the byte count, `0`
/// when no complete line is waiting (non-blocking — `yield_now` and retry),
/// or a negative errno. `fd` must be `0` (stdin).
#[inline]
pub fn read(fd: u64, buf: &mut [u8]) -> i64 {
    arch::syscall3(NR_READ, fd, buf.as_mut_ptr() as u64, buf.len() as u64)
}

/// Geometry of the kernel's VGA text console. `None` when the mirror is
/// off or the syscall failed. Encoded as `cols | rows << 16` on the wire.
#[inline]
pub fn console_dims() -> Option<(u16, u16)> {
    let packed = arch::syscall0(NR_VGA_DIMS);
    if packed < 0 {
        None
    } else {
        let packed = packed as u64;
        Some((packed as u16, (packed >> 16) as u16))
    }
}

/// Stage one raw text cell in the kernel's off-screen buffer. No hardware
/// write until [`vga_flush`]. `attr` is the VGA attribute byte
/// (`fg | bg << 4`). Returns `0` on success, a negative errno otherwise.
#[inline]
pub fn vga_put_cell(x: u16, y: u16, glyph: u8, attr: u8) -> i64 {
    arch::syscall4(
        NR_VGA_PUT_CELL,
        x as u64,
        y as u64,
        glyph as u64,
        attr as u64,
    )
}

/// Blank the kernel's staged cell buffer (no hardware write).
#[inline]
pub fn vga_clear() -> i64 {
    arch::syscall0(NR_VGA_CLEAR)
}

/// Diff the staged cells against `0xb8000` and write only what changed.
#[inline]
pub fn vga_flush() -> i64 {
    arch::syscall0(NR_VGA_FLUSH)
}

/// Read one raw cell back from the hardware text buffer, or `None` when
/// the mirror is off or the coordinates are out of range.
#[inline]
pub fn vga_peek(x: u16, y: u16) -> Option<(u8, u8)> {
    let packed = arch::syscall2(NR_VGA_PEEK, x as u64, y as u64);
    if packed < 0 {
        None
    } else {
        let packed = packed as u64;
        Some((packed as u8, (packed >> 8) as u8))
    }
}

// --- Hito 4: filesystem syscalls -----------------------------------------

/// Open a volume path. `path` must be absolute, ≤256 bytes and free of
/// `.`/`..`; the kernel returns an opaque fd (negative = errno).
#[inline]
pub fn fs_open(path: &[u8], flags: u64) -> i64 {
    arch::syscall3(NR_OPEN, path.as_ptr() as u64, path.len() as u64, flags)
}

/// Close an opaque volume fd. `0` on success, negative errno otherwise.
#[inline]
pub fn fs_close(fd: i64) -> i64 {
    arch::syscall1(NR_CLOSE, fd as u64)
}

/// Read from an opaque volume fd into `buf`. Byte count or negative errno.
#[inline]
pub fn fs_read(fd: i64, buf: &mut [u8]) -> i64 {
    arch::syscall3(
        NR_FS_READ,
        fd as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

/// Write `buf` to an opaque volume fd. Byte count or negative errno.
#[inline]
pub fn fs_write(fd: i64, buf: &[u8]) -> i64 {
    arch::syscall3(
        NR_FS_WRITE,
        fd as u64,
        buf.as_ptr() as u64,
        buf.len() as u64,
    )
}

/// Fill `out` (≥[`STAT_LEN`] bytes) with the fd's stat record. Returns the
/// record length or a negative errno.
#[inline]
pub fn fs_stat(fd: i64, out: &mut [u8]) -> i64 {
    arch::syscall3(
        NR_STAT,
        fd as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    )
}

/// Fill `out` with whole [`DIRENT_LEN`] records for a directory fd.
/// Returns bytes written (a multiple of [`DIRENT_LEN`]) or an errno.
#[inline]
pub fn fs_readdir(fd: i64, out: &mut [u8]) -> i64 {
    arch::syscall3(
        NR_READDIR,
        fd as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    )
}

/// Decode the little-endian `size` field of a `Stat` record. `None` when
/// the record is short. No allocation, no panic.
#[inline]
pub fn stat_size(record: &[u8]) -> Option<u64> {
    if record.len() < STAT_LEN {
        return None;
    }
    let mut size = 0u64;
    for (i, b) in record[..8].iter().enumerate() {
        size |= (*b as u64) << (8 * i);
    }
    Some(size)
}

/// Decode one `Readdir` record's name into `out`; `None` for a malformed
/// record. The returned slice borrows `out`.
#[inline]
pub fn dirent_name<'a>(record: &[u8], out: &'a mut [u8; DIRENT_NAME]) -> Option<&'a [u8]> {
    if record.len() < DIRENT_LEN {
        return None;
    }
    let n = record[1] as usize;
    if n == 0 || n > DIRENT_NAME {
        return None;
    }
    out[..n].copy_from_slice(&record[2..2 + n]);
    Some(&out[..n])
}

// --- Hito 5: network syscalls ---------------------------------------------

/// Resolve `name` through the kernel-owned DNS socket. On success writes
/// four IPv4 octets into `out[..4]` and returns them packed **big-endian**
/// (`10.0.2.3` → `0x0a00_0203`); a negative value is an errno. Only IPv4
/// literals and hosts on the kernel's TLS/DNS whitelist are accepted —
/// the kernel never hands a resolver object to user space.
#[inline]
pub fn dns_resolve(name: &[u8], out: &mut [u8]) -> i64 {
    arch::syscall4(
        NR_DNS_RESOLVE,
        name.as_ptr() as u64,
        name.len() as u64,
        out.as_mut_ptr() as u64,
        out.len() as u64,
    )
}

/// Open a TCP connection to `ip` (exactly four octets) and `port`. Returns
/// an opaque handle (negative = errno); the kernel owns the socket and
/// polls it, the process only ever holds the handle.
#[inline]
pub fn sock_connect(ip: &[u8], port: u16) -> i64 {
    arch::syscall3(
        NR_SOCK_CONNECT,
        ip.as_ptr() as u64,
        ip.len() as u64,
        port as u64,
    )
}

/// Send up to `bytes.len()` bytes on an opaque socket handle.
#[inline]
pub fn sock_send(handle: i64, bytes: &[u8]) -> i64 {
    arch::syscall3(
        NR_SOCK_SEND,
        handle as u64,
        bytes.as_ptr() as u64,
        bytes.len() as u64,
    )
}

/// Receive bytes into `buf`. Returns the byte count, `0` on peer FIN or
/// [`EAGAIN`] when nothing is ready yet (then `yield_now` and retry), or a
/// negative errno.
#[inline]
pub fn sock_recv(handle: i64, buf: &mut [u8]) -> i64 {
    arch::syscall3(
        NR_SOCK_RECV,
        handle as u64,
        buf.as_mut_ptr() as u64,
        buf.len() as u64,
    )
}

/// Close an opaque socket handle. `0` on success, negative errno otherwise.
#[inline]
pub fn sock_close(handle: i64) -> i64 {
    arch::syscall1(NR_SOCK_CLOSE, handle as u64)
}

/// Upgrade a connected plain handle to TLS for `host`. The kernel checks
/// `host` against the pinned-root whitelist before doing any handshake and
/// returns a **new** opaque handle (negative = errno).
#[inline]
pub fn tls_upgrade(handle: i64, host: &[u8]) -> i64 {
    arch::syscall3(
        NR_TLS_UPGRADE,
        handle as u64,
        host.as_ptr() as u64,
        host.len() as u64,
    )
}

/// The one piece of unsafe in this crate: the raw `int 0x80` wrappers.
mod arch {
    #![allow(unsafe_code)]

    /// Invoke a syscall with no arguments.
    #[inline(always)]
    pub fn syscall0(nr: u64) -> i64 {
        // SAFETY: `int 0x80` is the ABI's entry gate; no memory is passed.
        unsafe { raw(nr, 0, 0, 0, 0, 0, 0) }
    }

    /// Invoke a syscall with one argument.
    #[inline(always)]
    pub fn syscall1(nr: u64, a1: u64) -> i64 {
        // SAFETY: a1 is an integer/small scalar; it is the caller's job to
        // pass valid values for the chosen syscall number.
        unsafe { raw(nr, a1, 0, 0, 0, 0, 0) }
    }

    /// Invoke a syscall with two arguments (hito 3: `vga_peek`).
    #[inline(always)]
    pub fn syscall2(nr: u64, a1: u64, a2: u64) -> i64 {
        // SAFETY: a1/a2 are bounded integer coordinates; the kernel
        // validates them before touching hardware.
        unsafe { raw(nr, a1, a2, 0, 0, 0, 0) }
    }

    /// Invoke a syscall with three arguments (write's ABI).
    #[inline(always)]
    pub fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
        // SAFETY: a2/a3 are a user buffer pointer and length; the kernel
        // validates them with copy_from_user before any dereference. The
        // slice borrow in `write` keeps the buffer alive for the call.
        unsafe { raw(nr, a1, a2, a3, 0, 0, 0) }
    }

    /// Invoke a syscall with four arguments (hito 3: `vga_put_cell`).
    #[inline(always)]
    pub fn syscall4(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
        // SAFETY: all four are bounded integers; the kernel checks the
        // coordinates and the cell bytes before any hardware write.
        unsafe { raw(nr, a1, a2, a3, a4, 0, 0) }
    }

    /// Raw gate. `rax` = number in / i64 result out; args in SysV registers.
    ///
    /// # Safety
    /// The caller must use a valid syscall number and arguments; the kernel
    /// validates every user pointer and never trusts the buffer contents.
    #[inline(always)]
    unsafe fn raw(nr: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64) -> i64 {
        let ret: i64;
        // SAFETY: `int 0x80` transfers control to the kernel's DPL3 gate;
        // `rax`/`rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9` are the documented ABI
        // registers. No `nomem`: the kernel may read the pointed-to user
        // buffer. `nostack`: the instruction itself does not touch our stack
        // (the CPU switches to the kernel stack for the CPL3→0 transition).
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
