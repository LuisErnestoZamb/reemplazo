//! User network syscalls (hito 5) — numbers 16..=21.
//!
//! **Additive by design.** This module never edits `syscall.rs`; it exposes
//! [`dispatch_net`] for the integrator's default match arm:
//!
//! ```text
//! n => crate::userland::console::dispatch_extra(n, args)
//!         .or_else(|| crate::userland::fs::dispatch_fs(n, args))
//!         .or_else(|| crate::userland::net::dispatch_net(n, args))
//!         .unwrap_or(ENOSYS),
//! ```
//!
//! The kernel keeps `netstack::Stack` (smoltcp) and `tls` in ring 0. A
//! process supplies only bounded byte buffers, checked by
//! [`userptr`](super::userptr) before any dereference, and receives an
//! **opaque** handle: neither a socket index nor a `SocketHandle` nor a
//! resolver object ever crosses the boundary. Handles are tagged and
//! indexed by the current PCB's PID, exactly like hito 4's fds.
//!
//! # Integrator surface (two lines outside this file)
//!
//! 1. `kernel/src/main.rs`, next to `capture_hello` / after the stack is
//!    built: `crate::userland::net::register(stack.as_mut());` — this is the
//!    only place that hands the kernel-owned stack to this module.
//! 2. `kernel/src/userland/mod.rs`: `pub mod net;` plus the `dispatch_net`
//!    arm above.
//!
//! `register` stores a raw pointer; single core + the `int 0x80` gate's
//! interrupt masking mean no second `&mut Stack` can be live while a
//! syscall runs. The five pool sockets are the boot-chain sockets that are
//! already in `Closed`/`TimeWait` by the time a user process runs (AI,
//! browser, git and ssh phases all precede it). A TLS session owns its
//! socket until `SockClose`; while one is open, plain-socket calls are
//! refused so no aliasing `&mut Stack` is created.
//!
//! Errnos reuse the ABI set plus `EAGAIN` (`-11`) for a non-blocking
//! `SockRecv`: the caller yields and retries, as requested by the hito-5
//! plan. [`block_current`] is the optional real-`Blocked` request; the
//! integrator line that consumes it is documented on that function.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};

use embedded_tls::blocking::Aes128GcmSha256;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

use crate::clock;
use crate::netstack::Stack;

use super::process::MAX_PROCS;
use super::sched::current_pid;
use super::syscall::{EINVAL, EPERM};
use super::userptr;

// --- Stable syscall numbers (mirrored in `userlib`) -----------------------
/// `DnsResolve(name, buf, len) -> ip` (16).
pub const NR_DNS_RESOLVE: u64 = 16;
/// `SockConnect(ip, port) -> handle` (17).
pub const NR_SOCK_CONNECT: u64 = 17;
/// `SockSend(handle, buf, len) -> bytes` (18).
pub const NR_SOCK_SEND: u64 = 18;
/// `SockRecv(handle, buf, len) -> bytes | EAGAIN` (19).
pub const NR_SOCK_RECV: u64 = 19;
/// `SockClose(handle) -> 0` (20).
pub const NR_SOCK_CLOSE: u64 = 20;
/// `TlsUpgrade(handle, hostname) -> handle` (21).
pub const NR_TLS_UPGRADE: u64 = 21;

/// No data ready yet; the process should `yield_now()` and retry. Mirrored
/// in `userlib` (the milestone-1 errno table has no EAGAIN of its own).
pub const EAGAIN: i64 = -11;

/// Longest hostname accepted from user space.
const NAME_CAP: usize = 128;
/// Same cap for a wire-format IPv4 address (exactly four octets expected).
const IP_CAP: usize = 4;
/// Bounded kernel staging for one `SockRecv` (`userptr`'s 64 KiB cap stays
/// the outer bound; a single poll never produces anywhere near that).
const RECV_STAGE: usize = 2048;
/// Per-operation deadline (wall clock ms), bounded even if the mock dies.
const OP_MS: u64 = 5_000;
/// Local ports for the user sockets begin above every boot-chain port
/// (49152..=49167), so a lingering TIME-WAIT never collides.
const LOCAL_PORT_BASE: u16 = 49_200;
/// Four plain sockets per process is plenty for this milestone and keeps
/// the static table tiny. The fifth pool socket is reserved for TLS.
const POOL_PLAIN: usize = 4;
const POOL_LEN: usize = POOL_PLAIN + 1;
const MAX_SOCKS: usize = MAX_PROCS * POOL_PLAIN;

/// Hosts whose chains terminate at the pinned USERTrust ECC root already
/// used by `tls.rs`. Nothing else may be handed to an embedded-tls
/// handshake: a user-supplied hostname cannot widen the trust anchor.
const TLS_HOSTS: &[&str] = &["github.com", "api.github.com"];

/// Sockets are tagged so a console fd, a volume fd or a random integer can
/// never alias a network handle.
const SOCK_TAG: u64 = 0x8000_0000;

// --- Kernel stack registry ------------------------------------------------
static STACK_PTR: AtomicU64 = AtomicU64::new(0);

/// Pool of kernel-owned `SocketHandle`s, captured from the live stack by
/// [`register`]. `SocketHandle`'s field is private to smoltcp, so handles
/// are copied by value instead of reconstructed from an integer.
struct HandlePool(UnsafeCell<[Option<SocketHandle>; POOL_LEN]>);

// SAFETY: written once by `register` on the single boot core with
// interrupts off, read only from hito-5 syscalls on that same core while
// the `int 0x80` gate has IF=0. No concurrent access exists.
unsafe impl Sync for HandlePool {}

static POOL: HandlePool = HandlePool(UnsafeCell::new([None; POOL_LEN]));

/// Give this module access to the kernel-owned network stack. Called once
/// from `main.rs`, before any user process can issue a syscall. The pointer
/// is stored as an integer (no `&mut` outlives this call).
pub fn register(stack: &mut Stack) {
    STACK_PTR.store(stack as *mut Stack as u64, Ordering::Relaxed);
    // SAFETY: single-core boot, IF=0, `register` is called once before any
    // reader. All five source handles belong to this stack's socket set.
    let pool = unsafe { &mut *POOL.0.get() };
    pool[0] = Some(stack.tcp5_handle);
    pool[1] = Some(stack.tcp6_handle);
    pool[2] = Some(stack.tcp7_handle);
    pool[3] = Some(stack.tcp8_handle);
    pool[4] = Some(stack.tcp9_handle);
}

fn pool_handle(index: usize) -> Option<SocketHandle> {
    if index >= POOL_LEN {
        return None;
    }
    // SAFETY: `register` filled the pool before any user syscall can run;
    // single core, IF=0 in the gate, and the entries are `Copy`.
    unsafe { (*POOL.0.get())[index] }
}

/// Drive one stack iteration so netlog (and any other socket-backed
/// service) makes progress while userland runs without the boot network
/// chain. Fail-soft: no registered stack → no-op.
pub fn pump() {
    let _ = with_stack(|stack| stack.poll());
}

/// Run `f` with the registered kernel stack. `None` means the integrator
/// did not call `register` (fail closed — no user process can touch the
/// network stack by accident).
fn with_stack<R>(f: impl FnOnce(&mut Stack) -> R) -> Option<R> {
    let ptr = STACK_PTR.load(Ordering::Relaxed);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `register` received `&mut Stack` from `main.rs` and stored
    // only its address. The stack is a pinned local that outlives every
    // user syscall; one core and IF=0 in the `int 0x80` gate guarantee no
    // other `&mut Stack` is live during `f`. A live TLS session is checked
    // by `tls_busy()` before any plain-socket call creates a second borrow.
    let stack = unsafe { &mut *(ptr as *mut Stack) };
    Some(f(stack))
}

// --- Handle table ---------------------------------------------------------
struct Socket {
    used: AtomicU8,
    pid: AtomicU32,
    /// Index into `POOL`, not a smoltcp handle.
    pool: AtomicU8,
    /// Remote address, retained so `TlsUpgrade` can reconnect to the same
    /// peer on the dedicated TLS pool socket.
    ip: AtomicU32,
    /// 1 once the handle refers to the TLS session (TLS owns its socket).
    tls: AtomicU8,
}

impl Socket {
    const fn new() -> Self {
        Self {
            used: AtomicU8::new(0),
            pid: AtomicU32::new(u32::MAX),
            pool: AtomicU8::new(0),
            ip: AtomicU32::new(0),
            tls: AtomicU8::new(0),
        }
    }
}

static SOCKS: [Socket; MAX_SOCKS] = [const { Socket::new() }; MAX_SOCKS];

fn encode(index: usize) -> i64 {
    (SOCK_TAG | index as u64) as i64
}

fn find(handle: i64, pid: u32) -> Option<usize> {
    let h = handle as u64;
    if h < SOCK_TAG {
        return None;
    }
    let index = (h - SOCK_TAG) as usize;
    let entry = SOCKS.get(index)?;
    if entry.used.load(Ordering::Relaxed) == 0 || entry.pid.load(Ordering::Relaxed) != pid {
        return None;
    }
    Some(index)
}

fn claim(pid: u32) -> Option<usize> {
    let base = (pid as usize).saturating_mul(POOL_PLAIN);
    for local in 0..POOL_PLAIN {
        let index = base + local;
        if index >= SOCKS.len() {
            return None;
        }
        let entry = &SOCKS[index];
        if entry.used.load(Ordering::Relaxed) == 0 {
            return Some(index);
        }
    }
    None
}

// --- TLS session ----------------------------------------------------------
type Session =
    embedded_tls::blocking::TlsConnection<'static, crate::tls::Stream<'static>, Aes128GcmSha256>;

struct SessionSlot(UnsafeCell<Option<Session>>);

// SAFETY: one core, IF=0 in the gate, and `tls_busy()` prevents a second
// borrow of the stack while a TLS session is live. The slot is touched
// only from these syscalls on the single boot core.
unsafe impl Sync for SessionSlot {}

static SESSION: SessionSlot = SessionSlot(UnsafeCell::new(None));

fn tls_busy() -> bool {
    // SAFETY: see `SessionSlot`. The Option tag is read atomically-ish on
    // one core with interrupts masked by the gate; no writer races it.
    unsafe { (*SESSION.0.get()).is_some() }
}

/// Close and forget any live TLS session. Called from `SockClose` and
/// `release_pid`; the connection borrows the kernel stack, so it must be
/// dropped before any other socket syscall creates a fresh `&mut Stack`.
fn drop_session() {
    // SAFETY: single core, IF=0 in the gate, and the caller checked that
    // the calling PID owns the TLS handle before reaching this point.
    unsafe { *SESSION.0.get() = None };
}

// --- Buffer helpers -------------------------------------------------------

/// Copy kernel bytes into a validated user buffer. `userptr::validate`
/// re-checks the range at write time (no `&mut` is created until then).
fn copy_out(ptr: u64, bytes: &[u8]) -> i64 {
    if let Err(e) = userptr::validate(ptr, bytes.len()) {
        return e;
    }
    // SAFETY: `userptr::validate` proved the whole `ptr..ptr+len` range
    // lies inside one registered user VMA and inside the user window,
    // with `len <= 64 KiB`; the CPL3 process cannot run concurrently
    // (single core, IF=0 in the `int 0x80` gate), and no reference
    // survives this call.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr as *mut u8, bytes.len()) };
    bytes.len() as i64
}

fn packed_ip(octets: [u8; 4]) -> i64 {
    u32::from_be_bytes(octets) as i64
}

fn whitelisted(host: &str) -> bool {
    TLS_HOSTS.contains(&host)
}

// --- Syscalls -------------------------------------------------------------

fn sys_dns(name_ptr: u64, name_len: u64, out_ptr: u64, out_len: u64) -> i64 {
    if name_len == 0 || name_len > NAME_CAP as u64 || out_len < IP_CAP as u64 {
        return EINVAL;
    }
    let name_bytes = match userptr::validated_slice(name_ptr, name_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let name = match core::str::from_utf8(name_bytes) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };
    // An IPv4 literal is resolved locally: the mock's DNS server address
    // (`10.0.2.3`) is reachable without any outbound DNS query, so this
    // proof stays offline. Named hosts go through the kernel resolver,
    // but only if they are on the pinned-root whitelist.
    let octets = match net::parse_ipv4(name) {
        Some(ip) => ip, // local: no stack borrow, safe beside a TLS session
        None if whitelisted(name) => {
            // A live TLS session owns the only `&mut Stack`; a named DNS
            // query would alias it. Fail closed instead.
            if tls_busy() {
                return EPERM;
            }
            let Some(ip) = with_stack(|s| s.resolve(name)).flatten() else {
                return EAGAIN;
            };
            ip.octets()
        }
        None => return EPERM,
    };
    let written = copy_out(out_ptr, &octets);
    if written < 0 {
        return written;
    }
    packed_ip(octets)
}

fn sys_connect(ip_ptr: u64, ip_len: u64, port: u64) -> i64 {
    if ip_len != IP_CAP as u64 || port == 0 || port > u16::MAX as u64 {
        return EINVAL;
    }
    if tls_busy() {
        return EPERM;
    }
    let bytes = match userptr::validated_slice(ip_ptr, IP_CAP) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let mut octets = [0u8; IP_CAP];
    octets.copy_from_slice(bytes);
    let ip = Ipv4Address::new(octets[0], octets[1], octets[2], octets[3]);
    let pid = current_pid();
    let Some(index) = claim(pid) else {
        return EPERM; // per-process socket table full
    };
    let Some(handle) = pool_handle(index % POOL_PLAIN) else {
        return EPERM; // integrator did not register the stack
    };
    let local_port = LOCAL_PORT_BASE.saturating_add(index as u16);
    let connected = with_stack(|stack| {
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if sock.is_open() {
                sock.abort(); // a previous user handle left it mid-flight
            }
        }
        stack.poll();
        if stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .connect(stack.iface.context(), (ip, port as u16), local_port)
            .is_err()
        {
            return false;
        }
        let deadline = clock::now_ms() + OP_MS;
        loop {
            stack.poll();
            if stack.sockets.get::<tcp::Socket>(handle).state() == tcp::State::Established {
                return true;
            }
            if clock::now_ms() > deadline {
                return false;
            }
        }
    })
    .unwrap_or(false);
    if !connected {
        return EAGAIN;
    }
    let entry = &SOCKS[index];
    entry
        .ip
        .store(u32::from_be_bytes(octets), Ordering::Relaxed);
    entry
        .pool
        .store((index % POOL_PLAIN) as u8, Ordering::Relaxed);
    entry.pid.store(pid, Ordering::Relaxed);
    entry.tls.store(0, Ordering::Relaxed);
    entry.used.store(1, Ordering::Relaxed);
    encode(index)
}

fn sys_send(handle: i64, buf: u64, len: u64) -> i64 {
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    let pid = current_pid();
    let Some(index) = find(handle, pid) else {
        return EINVAL;
    };
    let entry = &SOCKS[index];
    if entry.tls.load(Ordering::Relaxed) != 0 {
        let bytes = match userptr::validated_slice(buf, len as usize) {
            Ok(b) => b,
            Err(e) => return e,
        };
        // SAFETY: the only live `Session` was created by `TlsUpgrade` for
        // this PID; single core, IF=0, and `copy_out`/plain calls refuse
        // to touch the stack while it is live.
        let session = unsafe { &mut *SESSION.0.get() };
        let Some(conn) = session.as_mut() else {
            return EINVAL;
        };
        return match conn.write(bytes) {
            Ok(n) => n as i64,
            Err(_) => EAGAIN,
        };
    }
    if tls_busy() {
        return EPERM;
    }
    let bytes = match userptr::validated_slice(buf, len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let Some(socket_handle) = pool_handle(entry.pool.load(Ordering::Relaxed) as usize) else {
        return EINVAL;
    };
    with_stack(|stack| {
        let deadline = clock::now_ms() + OP_MS;
        let mut sent = 0usize;
        while sent < bytes.len() {
            stack.poll();
            match stack
                .sockets
                .get_mut::<tcp::Socket>(socket_handle)
                .send_slice(&bytes[sent..])
            {
                Ok(n) if n > 0 => sent += n,
                _ => {
                    if stack.sockets.get::<tcp::Socket>(socket_handle).state() == tcp::State::Closed
                    {
                        return sent as i64;
                    }
                    if clock::now_ms() > deadline {
                        return if sent == 0 { EAGAIN } else { sent as i64 };
                    }
                }
            }
        }
        sent as i64
    })
    .unwrap_or(EINVAL)
}

fn sys_recv(handle: i64, buf: u64, len: u64) -> i64 {
    if len > userptr::MAX_IO_LEN as u64 {
        return EINVAL;
    }
    let pid = current_pid();
    let Some(index) = find(handle, pid) else {
        return EINVAL;
    };
    let entry = &SOCKS[index];
    if len == 0 {
        return 0;
    }
    if let Err(e) = userptr::validate(buf, len as usize) {
        return e;
    }
    if entry.tls.load(Ordering::Relaxed) != 0 {
        // SAFETY: see `sys_send`. The session belongs to this PID's handle.
        let session = unsafe { &mut *SESSION.0.get() };
        let Some(conn) = session.as_mut() else {
            return EINVAL;
        };
        let mut staged = [0u8; RECV_STAGE];
        let take = staged.len().min(len as usize);
        return match conn.read(&mut staged[..take]) {
            Ok(0) => 0, // orderly TLS close
            Ok(n) => {
                let w = copy_out(buf, &staged[..n]);
                if w < 0 { w } else { n as i64 }
            }
            Err(_) => EAGAIN,
        };
    }
    if tls_busy() {
        return EPERM;
    }
    let Some(socket_handle) = pool_handle(entry.pool.load(Ordering::Relaxed) as usize) else {
        return EINVAL;
    };
    // Bounded internal polling (≤64 iterations / 2 ms): short enough to
    // stay non-blocking from the process's point of view, long enough that
    // a just-sent request's reply normally arrives in the same syscall —
    // so the process rarely has to `Yield` and retry. Staging in kernel
    // memory keeps no `&mut` to user pages alive across `stack.poll()`.
    let mut staged = [0u8; RECV_STAGE];
    let got = with_stack(|stack| {
        let deadline = clock::now_ms() + 10;
        for _ in 0..64 {
            stack.poll();
            let sock = stack.sockets.get_mut::<tcp::Socket>(socket_handle);
            let take = staged.len().min(len as usize);
            let n = sock.recv_slice(&mut staged[..take]).unwrap_or(0);
            let fin = !sock.may_recv() && sock.recv_queue() == 0;
            if n > 0 || fin || clock::now_ms() > deadline {
                return (n, fin);
            }
        }
        (0, false)
    })
    .unwrap_or((0, false));
    if got.0 > 0 {
        let w = copy_out(buf, &staged[..got.0]);
        return if w < 0 { w } else { got.0 as i64 };
    }
    if got.1 {
        0 // peer FIN with no data left
    } else {
        EAGAIN
    }
}

fn sys_close(handle: i64) -> i64 {
    let pid = current_pid();
    let Some(index) = find(handle, pid) else {
        return EINVAL;
    };
    let entry = &SOCKS[index];
    if entry.tls.load(Ordering::Relaxed) != 0 {
        drop_session();
    } else if !tls_busy()
        && let Some(socket_handle) = pool_handle(entry.pool.load(Ordering::Relaxed) as usize)
    {
        let _ = with_stack(|stack| {
            stack.sockets.get_mut::<tcp::Socket>(socket_handle).abort();
        });
    }
    entry.used.store(0, Ordering::Relaxed);
    entry.tls.store(0, Ordering::Relaxed);
    0
}

fn sys_tls_upgrade(handle: i64, host_ptr: u64, host_len: u64) -> i64 {
    if host_len == 0 || host_len > NAME_CAP as u64 {
        return EINVAL;
    }
    let bytes = match userptr::validated_slice(host_ptr, host_len as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let host = match core::str::from_utf8(bytes) {
        Ok(h) => h,
        Err(_) => return EINVAL,
    };
    // Trust is fixed: only hosts whose pinned-root chain the existing TLS
    // milestone validates may be upgraded. No wildcard, no suffix match.
    if !whitelisted(host) {
        return EPERM;
    }
    let pid = current_pid();
    let Some(index) = find(handle, pid) else {
        return EINVAL;
    };
    if tls_busy() {
        return EPERM;
    }
    let entry = &SOCKS[index];
    let ip_packed = entry.ip.load(Ordering::Relaxed);
    let Some(handle_plain) = pool_handle(entry.pool.load(Ordering::Relaxed) as usize) else {
        return EINVAL;
    };
    let Some(handle_tls) = pool_handle(POOL_PLAIN) else {
        return EINVAL;
    };
    let raw = ip_packed.to_be_bytes();
    let ip = Ipv4Address::new(raw[0], raw[1], raw[2], raw[3]);
    let local_port = LOCAL_PORT_BASE.saturating_add(POOL_PLAIN as u16);
    // The plain connection is dropped: `tls_open` connects its own socket
    // to :443 against the same IP. The old handle is no longer usable.
    let _ = with_stack(|stack| {
        stack.sockets.get_mut::<tcp::Socket>(handle_plain).abort();
    });
    let connected = with_stack(|stack| {
        // SAFETY: `tls_open` borrows this stack for the lifetime of the
        // session. The borrow is transmuted to 'static below so it can be
        // stored in `SESSION`; `tls_busy()` then forbids every other
        // stack-touching syscall until `SockClose` drops the session.
        let session = crate::tls::tls_open(stack, handle_tls, ip, host, local_port);
        // SAFETY: the stack address is stable (`register`), single core,
        // IF=0, and no other borrow is created while the session is live.
        let session: Session = unsafe { core::mem::transmute(session) };
        // SAFETY: `SESSION` is single-core, IF=0, and `tls_busy()` was
        // false on entry; no other writer can race this store.
        unsafe { *SESSION.0.get() = Some(session) };
        true
    })
    .unwrap_or(false);
    if !connected {
        return EAGAIN;
    }
    // Reuse the same opaque handle, but flag it as TLS so send/recv route
    // through the session and a later close drops it.
    entry.tls.store(1, Ordering::Relaxed);
    encode(index)
}

/// Dispatch one hito-5 syscall. `None` means "not mine", so the caller's
/// `ENOSYS` fallthrough stays unchanged.
pub fn dispatch_net(nr: u64, args: [u64; 6]) -> Option<i64> {
    let ret = match nr {
        NR_DNS_RESOLVE => sys_dns(args[0], args[1], args[2], args[3]),
        NR_SOCK_CONNECT => sys_connect(args[0], args[1], args[2]),
        NR_SOCK_SEND => sys_send(args[0] as i64, args[1], args[2]),
        NR_SOCK_RECV => sys_recv(args[0] as i64, args[1], args[2]),
        NR_SOCK_CLOSE => sys_close(args[0] as i64),
        NR_TLS_UPGRADE => sys_tls_upgrade(args[0] as i64, args[1], args[2]),
        _ => return None,
    };
    Some(ret)
}

// --- Optional real `Blocked` state ----------------------------------------
static BLOCK_REQUEST: AtomicBool = AtomicBool::new(false);

/// Ask the integrator's `syscall_hook` to put the current process into the
/// scheduler's real `Blocked` state (the scheduler already has `block`/
/// `unblock`; this module must not touch it). The user process does **not**
/// need this: it polls `SockRecv`, gets `EAGAIN` and calls `Yield`.
pub fn block_current() {
    BLOCK_REQUEST.store(true, Ordering::Relaxed);
}

/// Consume a pending [`block_current`] request. Integrator line, in
/// `userland/mod.rs`'s `syscall_hook`, **after** `dispatch_resume`:
///
/// ```text
/// if crate::userland::net::take_block_request() {
///     let pid = crate::userland::sched::current_pid();
///     let _ = crate::userland::sched::block(pid);
///     return crate::userland::sched::yield_current(f);
/// }
/// ```
pub fn take_block_request() -> bool {
    BLOCK_REQUEST.swap(false, Ordering::Relaxed)
}

/// Release every socket a terminated process still owns. Optional
/// integrator line in the `Exit` path (without it the table keeps a
/// tombstoned PID's entries, which no other PID can use).
pub fn release_pid(pid: u32) {
    for entry in SOCKS.iter() {
        if entry.pid.load(Ordering::Relaxed) == pid && entry.used.load(Ordering::Relaxed) != 0 {
            if entry.tls.load(Ordering::Relaxed) != 0 {
                drop_session();
            }
            entry.used.store(0, Ordering::Relaxed);
            entry.tls.store(0, Ordering::Relaxed);
        }
    }
}
