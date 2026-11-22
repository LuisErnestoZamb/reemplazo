//! Round-robin scheduler — **milestone 1 is cooperative** (switch only on
//! `Yield`/`Exit`); tick-driven preemption is milestone 2 and is gated by
//! [`SCHED_ACTIVE`] / [`PREEMPT_USER_ONLY`].
//!
//! # Ownership contract (read before editing)
//!
//! `entry.S`, `idt.rs`, `interrupts.S`, `pit.rs`, GDT6/TSS, the `int 0x80`
//! stub and the `idt::Frame` layout belong to **m-privilege**, not us. We
//! use `idt::Frame` only as an opaque pointer type: `schedule()` stores and
//! returns frame pointers without reading a single field in milestone 1.
//! That is what makes this module compile before/while m-privilege changes
//! the layout to include `user_rsp`/`user_ss`.
//!
//! m-privilege's `isr_common` returns the frame pointer to restore in `rax`.
//! Our part of that handshake is [`schedule`]: save the incoming frame into
//! the current PCB, pick the next `Ready` process, install `TSS.RSP0`, load
//! CR3, and return the next PCB's frame. The syscall handler calls it for
//! `Yield`/`Exit`; the IRQ0 handler calls [`on_tick`], which **never
//! switches** (no recursion from IRQ context, PID0 is never preempted).
//!
//! All mutable state is behind one `static mut` touched only inside an
//! [`IrqGuard`] critical section: single core, IF=0, no nested mutation.
//! Queue operations use `match`/`Option` only — no `unwrap`/`expect`.

// Milestone 2 lands these entry points in stages: `on_tick`/`schedule` are
// wired by m-privilege, `spawn`/`block`/`install_frame` by the ELF and
// syscall milestones. Keep the blueprint's whole surface visible under
// `-D warnings` instead of hiding it behind `cfg`.
#![allow(dead_code)]

use crate::idt::Frame as InterruptFrame;
use crate::userland::process::{KERNEL_STACK_SIZE, MAX_PROCS, Process, State};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// PIT is 100 Hz ([`crate::pit::HZ`]); 10 ticks = 100 ms quantum.
const QUANTUM_TICKS: u32 = 10;

/// 64-bit TSS descriptor in the GDT. m-privilege installs GDT6; before that
/// lands, `tss_rsp0_addr` returns `None` and the RSP0 write is skipped
/// (documented deviation, no effect on the milestone-1 proof).
const TSS_GDT_INDEX: usize = 6;
/// `RSP0` sits at byte offset 4 in the 64-bit TSS.
const TSS_RSP0_OFFSET: u64 = 4;

/// Conventional flat 64-bit user selectors. **m-privilege owns the GDT** —
/// if its user selectors differ, change these two constants there or here;
/// they are used only when synthesizing a brand-new CPL3 frame.
const USER_CS: u64 = 0x2b;
const USER_SS: u64 = 0x23;
const RFLAGS_IF: u64 = 1 << 9;

/// Set by the owner once real user processes may be preempted. Off in
/// milestone 1, so [`on_tick`] only accounts ticks.
static SCHED_ACTIVE: AtomicBool = AtomicBool::new(false);
/// When true (the default), the tick never preempts PID0 (ring 0).
static PREEMPT_USER_ONLY: AtomicBool = AtomicBool::new(true);
/// Latched by [`on_tick`] when a quantum expires; consumed at the next safe
/// point via [`take_resched_frame`] so the switch is never done in the IRQ.
static NEED_RESCHED: AtomicBool = AtomicBool::new(false);
/// Number of successful context switches (proof + diagnostics).
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// 16-byte aligned backing store: `iretq` and SysV both want alignment.
#[repr(align(16))]
struct KernelStack([u8; KERNEL_STACK_SIZE]);

static mut KERNEL_STACKS: [KernelStack; MAX_PROCS] =
    [const { KernelStack([0; KERNEL_STACK_SIZE]) }; MAX_PROCS];

/// All scheduler state. PID0 is slot 0 and is `Running` after [`reset`].
struct Scheduler {
    procs: [Process; MAX_PROCS],
    /// Ring of pids; a slot stays in the ring while `Ready`/`Running`/
    /// `Blocked`/`Exited` and is skipped by the picker unless `Ready`.
    queue: [u32; MAX_PROCS],
    len: usize,
    head: usize,
    current_pid: u32,
    next_pid: u32,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            procs: [const { Process::empty() }; MAX_PROCS],
            queue: [0; MAX_PROCS],
            len: 0,
            head: 0,
            current_pid: 0,
            next_pid: 1,
        }
    }

    /// pid → slot is identity: pid == slot index. Bounds-checked, no panic.
    fn proc(&self, pid: u32) -> Option<&Process> {
        usize::try_from(pid).ok().and_then(|i| self.procs.get(i))
    }

    fn proc_mut(&mut self, pid: u32) -> Option<&mut Process> {
        usize::try_from(pid)
            .ok()
            .and_then(|i| self.procs.get_mut(i))
    }

    /// Position of `pid` in the live prefix of the ring.
    fn queue_index(&self, pid: u32) -> Option<usize> {
        self.queue.get(..self.len)?.iter().position(|&p| p == pid)
    }

    /// Scan at most `len` entries starting at `from`, wrapping. `len == 0`
    /// is handled before any modulo, so no division by zero is possible.
    fn next_ready(&self, from: usize) -> Option<usize> {
        if self.len == 0 || self.len > MAX_PROCS {
            return None;
        }
        for k in 0..self.len {
            let idx = (from + k) % self.len;
            let pid = self.queue[idx];
            if let Some(p) = self.proc(pid)
                && p.state == State::Ready
            {
                return Some(idx);
            }
        }
        None
    }
}

static mut SCHED: Scheduler = Scheduler::new();

/// IF=0 while alive; `Drop` restores the caller's IF. Crucially, when the
/// guard is created from an IRQ handler IF is already 0, so `drop` does
/// **not** `sti` — we can never accidentally re-enable interrupts there.
struct IrqGuard {
    flags: u64,
}

impl IrqGuard {
    fn lock() -> Self {
        let flags: u64;
        // SAFETY: `pushfq`/`pop` reads RFLAGS without changing it; `cli`
        // masks maskable interrupts on this single core. No `nostack` —
        // `pushfq` touches the stack. No `preserves_flags`: `cli` changes IF.
        unsafe {
            core::arch::asm!("pushfq", "pop {}", "cli", out(reg) flags);
        }
        Self { flags }
    }
}

impl Drop for IrqGuard {
    fn drop(&mut self) {
        if self.flags & RFLAGS_IF != 0 {
            // SAFETY: IF was set when we entered, so re-enabling restores
            // exactly the caller's interrupt state.
            unsafe { core::arch::asm!("sti", options(nostack)) };
        }
    }
}

// SAFETY: all callers hold an `IrqGuard` (single core, IF=0) and never keep
// the reference past the guard's lifetime. The function is private to this
// module, so the invariant is local and checkable.
fn sched_mut() -> &'static mut Scheduler {
    // SAFETY: see above — unique access under IF=0.
    unsafe { &mut *core::ptr::addr_of_mut!(SCHED) }
}

/// Top (one-past-end) of a process's 4 KiB kernel stack.
fn kernel_stack_top(slot: usize) -> u64 {
    // SAFETY: `slot` is always a pid from our own bounded table; reading the
    // address of a static array element creates no reference to its bytes.
    let base = unsafe { core::ptr::addr_of!(KERNEL_STACKS[slot].0) } as u64;
    base + KERNEL_STACK_SIZE as u64
}

/// Read current CR3 (PID0's page table) with `mov reg, cr3`.
fn read_cr3() -> u64 {
    let value: u64;
    // SAFETY: reading CR3 in ring 0 is always legal; no memory/stack effect.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Address of `TSS.RSP0`, derived from GDT6 rather than from a static owned
/// by m-privilege — this keeps the module independent while still doing the
/// real TSS write once their GDT lands. `None` before then, or if index 6
/// is not a present 64-bit TSS (type 9).
fn tss_rsp0_addr() -> Option<u64> {
    let mut gdtr = [0u8; 10];
    // SAFETY: `sgdt` writes exactly 10 bytes into this local buffer; no
    // stack change. Not `readonly`: the instruction writes memory.
    unsafe {
        core::arch::asm!("sgdt [{}]", in(reg) gdtr.as_mut_ptr(), options(nostack));
    }
    // sgdt layout: limit u16 at 0..2, base u64 at 2..10.
    let gdt_base = u64::from_le_bytes([
        gdtr[2], gdtr[3], gdtr[4], gdtr[5], gdtr[6], gdtr[7], gdtr[8], gdtr[9],
    ]);
    if gdt_base == 0 {
        return None;
    }
    let desc_addr = gdt_base + (TSS_GDT_INDEX * 8) as u64;
    // SAFETY: the GDT is in the kernel's identity map for the whole boot;
    // a 16-byte system descriptor is aligned there and readable.
    let raw = unsafe { core::ptr::read_unaligned(desc_addr as *const [u8; 16]) };
    let access = raw[6];
    if access & 0x1f != 0x09 || access & 0x80 == 0 {
        return None; // not a present available 64-bit TSS yet
    }
    let base = u64::from(raw[2])
        | (u64::from(raw[3]) << 8)
        | (u64::from(raw[4]) << 16)
        | (u64::from(raw[5]) << 24)
        | (u64::from(raw[8]) << 32)
        | (u64::from(raw[9]) << 40)
        | (u64::from(raw[10]) << 48)
        | (u64::from(raw[11]) << 56);
    if base == 0 {
        return None;
    }
    Some(base + TSS_RSP0_OFFSET)
}

/// Install `pid`'s kernel stack / page table as the current hardware
/// context. Called inside `schedule` with IF=0.
fn install_context(s: &Scheduler, pid: u32) {
    let Some(p) = s.proc(pid) else {
        return;
    };
    if let Some(rsp0) = tss_rsp0_addr() {
        // SAFETY: `rsp0` came from a validated GDT6 TSS base in the
        // identity map; the write is 8 aligned bytes, IF=0, single-core.
        unsafe { core::ptr::write_volatile(rsp0 as *mut u64, p.kernel_stack_top) };
    }
    // SAFETY: loading CR3 in ring 0 is always legal. The value comes from
    // a PCB captured from our own page table (or the ELF loader).
    unsafe { core::arch::asm!("mov cr3, {}", in(reg) p.cr3_phys, options(nostack)) };
}

/// Build the first CPL3 interrupt frame at the top of a fresh process's
/// kernel stack and return its address.
///
/// # Safety
/// `frame` must point at least 24 bytes above `rflags` into writable kernel
/// stack memory. The `rip`/`cs`/`rflags` offsets come from m-privilege's
/// `idt::Frame`; its `user_rsp`/`user_ss` fields are expected to be the two
/// u64s appended right after `rflags` (their natural `iretq` order). If
/// m-privilege picks a different layout, adjust the two `+ 8` / `+ 16`
/// offsets here — this is the single coupling point, and milestone 1 never
/// calls it (its test frames are opaque).
unsafe fn build_user_frame(frame: *mut c_void, entry: u64, user_stack: u64) {
    let rip_off = core::mem::offset_of!(InterruptFrame, rip);
    let cs_off = core::mem::offset_of!(InterruptFrame, cs);
    let flags_off = core::mem::offset_of!(InterruptFrame, rflags);
    let base = frame as *mut u8;
    // SAFETY: see # Safety; all writes are 8-byte-aligned within the stack.
    unsafe {
        core::ptr::write_unaligned(base.add(rip_off) as *mut u64, entry);
        core::ptr::write_unaligned(base.add(cs_off) as *mut u64, USER_CS | 3);
        core::ptr::write_unaligned(base.add(flags_off) as *mut u64, RFLAGS_IF);
        core::ptr::write_unaligned(base.add(flags_off + 8) as *mut u64, user_stack);
        core::ptr::write_unaligned(base.add(flags_off + 16) as *mut u64, USER_SS | 3);
    }
}

/// Reset to a clean single-context state: PID0 `Running`, empty queue,
/// current CR3 captured. Also used by [`prove`] to leave no residue.
fn reset() {
    let _guard = IrqGuard::lock();
    let cr3 = read_cr3();
    let s = sched_mut();
    s.procs = [const { Process::empty() }; MAX_PROCS];
    let top = kernel_stack_top(0);
    s.procs[0] = Process::new(0, cr3, top, 0, 0);
    s.procs[0].state = State::Running;
    s.procs[0].saved_context = core::ptr::null_mut();
    s.queue = [0; MAX_PROCS];
    s.len = 1;
    s.head = 0;
    s.current_pid = 0;
    s.next_pid = 1;
    NEED_RESCHED.store(false, Ordering::Release);

    // Restore hardware state to PID0 as well (the proof may have written
    // RSP0/CR3 of a test process).
    install_context(s, 0);
}

/// Initialize the scheduler and run the milestone-1 self-proof, which emits
/// `SCHED_OK`. This is the single line the integrator adds to `main.rs`
/// (`crate::userland::sched::init();`) — place it after `pit::init()` so
/// ticks are safe, and before `shell::run` so PID0 is the idle context.
pub fn init() {
    reset();
    prove();
}

/// Create a `Ready` process with a default user stack value. See
/// [`spawn_with_stack`] for the full form.
pub fn spawn(entry: u64, cr3_phys: u64) -> Option<u32> {
    spawn_with_stack(entry, cr3_phys, 0)
}

/// Allocate a PCB and synthesize its first frame on its own kernel stack.
/// Returns `None` when the table is full or pids are exhausted — never
/// panics. The caller must have prepared `cr3_phys` (the ELF-loader
/// milestone) and `user_stack_top`.
pub fn spawn_with_stack(entry: u64, cr3_phys: u64, user_stack_top: u64) -> Option<u32> {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    if s.len >= MAX_PROCS {
        return None;
    }
    let pid = s.next_pid;
    let slot = usize::try_from(pid).ok()?;
    if slot >= MAX_PROCS {
        return None;
    }
    let top = kernel_stack_top(slot);
    // Reserve 16 bytes of alignment at the top for the synthesized frame.
    let frame = (top - 16) as *mut c_void;
    // SAFETY: `frame` is 16 bytes below a 16-byte-aligned 4 KiB stack top,
    // so all offset writes stay inside this process's stack.
    unsafe { build_user_frame(frame, entry, user_stack_top) };
    let mut p = Process::new(pid, cr3_phys, top, entry, user_stack_top);
    p.saved_context = frame;
    s.procs[slot] = p;
    s.queue[s.len] = pid;
    s.len += 1;
    s.next_pid = pid + 1;
    Some(pid)
}

/// Mark a process `Exited`. Its slot stays as a tombstone and is skipped
/// by the picker. Returns false for an unknown/already-unused pid.
pub fn exit(pid: u32) -> bool {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    match s.proc_mut(pid) {
        Some(p) if p.is_allocated() => {
            p.state = State::Exited;
            true
        }
        _ => false,
    }
}

/// Cooperative block/unblock (reserved for wait/sleep syscalls).
pub fn block(pid: u32) -> bool {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    match s.proc_mut(pid) {
        Some(p) if matches!(p.state, State::Running | State::Ready) => {
            p.state = State::Blocked;
            true
        }
        _ => false,
    }
}

pub fn unblock(pid: u32) -> bool {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    match s.proc_mut(pid) {
        Some(p) if p.state == State::Blocked => {
            p.state = State::Ready;
            true
        }
        _ => false,
    }
}

/// Replace a process's saved frame from outside — used by the ELF loader
/// once it has built a CPL3 frame with m-privilege's real layout.
pub fn install_frame(pid: u32, frame: *mut c_void) -> bool {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    match s.proc_mut(pid) {
        Some(p) if p.is_allocated() => {
            p.saved_context = frame;
            true
        }
        _ => false,
    }
}

/// The core cooperative switch. Returns the frame pointer that
/// `isr_common` (m-privilege) must restore:
///
/// 1. save `frame` into the current PCB (and demote `Running` → `Ready`);
/// 2. pick the next `Ready` pid in RR order (skipping PID0's idle slot
///    only if it is the sole candidate — PID0 is a normal ready context
///    when the shell resumes);
/// 3. install its `TSS.RSP0` + CR3;
/// 4. return its saved frame. With no other runnable process we return
///    the original frame, i.e. the current context simply continues.
pub fn schedule(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    let old_pid = s.current_pid;

    match s.proc_mut(old_pid) {
        Some(p) => {
            p.saved_context = frame.cast::<c_void>();
            if p.state == State::Running {
                p.state = State::Ready;
            }
        }
        None => return frame,
    }

    // The demoted current process is `Ready` too, so start the scan at the
    // slot *after* it — otherwise RR would immediately re-pick itself.
    if let Some(cur_idx) = s.queue_index(old_pid) {
        s.head = (cur_idx + 1) % s.len;
    }

    let next_idx = s.next_ready(s.head).or_else(|| s.next_ready(0));
    let Some(next_idx) = next_idx else {
        // Nobody else to run: resume the current context.
        if let Some(p) = s.proc_mut(old_pid) {
            p.state = State::Running;
        }
        return frame;
    };

    let next_pid = s.queue[next_idx];
    s.head = if s.len == 0 {
        0
    } else {
        (next_idx + 1) % s.len
    };
    s.current_pid = next_pid;
    if let Some(p) = s.proc_mut(next_pid) {
        p.state = State::Running;
    }
    install_context(s, next_pid);

    SWITCHES.fetch_add(1, Ordering::Relaxed);
    NEED_RESCHED.store(false, Ordering::Release);

    match s.proc(next_pid) {
        Some(p) if !p.saved_context.is_null() => p.saved_context.cast::<InterruptFrame>(),
        _ => frame,
    }
}

/// Syscall entry for `Yield`: same switch, current stays runnable.
pub fn yield_current(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    schedule(frame)
}

/// Syscall entry for `Exit`: mark the current process dead, then switch.
pub fn exit_current(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        let pid = s.current_pid;
        if let Some(p) = s.proc_mut(pid) {
            p.state = State::Exited;
        }
    } // release the exclusive borrow before `schedule` takes its own guard
    schedule(frame)
}

/// IRQ0 hook. **Exact signature required by m-privilege.**
///
/// Milestone 1: account the quantum and, once preemption is enabled
/// ([`set_active`]), latch [`NEED_RESCHED`] on expiry and remember the
/// interrupted frame — but never switch here. No IRQ recursion, no `sti`
/// from the guard, PID0 exempt when [`PREEMPT_USER_ONLY`] is set.
pub fn on_tick(frame: *mut InterruptFrame) {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    let pid = s.current_pid;
    if pid == 0 || !SCHED_ACTIVE.load(Ordering::Acquire) {
        return;
    }
    let Some(p) = s.proc_mut(pid) else {
        return;
    };
    // Milestone 2 refinement: `PREEMPT_USER_ONLY` is true means PID0 is
    // untouchable (already covered by `pid == 0`). The flag is exposed so
    // the policy can be widened/narrowed without touching this function.
    let _ = PREEMPT_USER_ONLY.load(Ordering::Acquire);
    p.saved_context = frame.cast::<c_void>();
    if p.quantum_left > 0 {
        p.quantum_left -= 1;
    }
    if p.quantum_left == 0 {
        p.quantum_left = QUANTUM_TICKS;
        NEED_RESCHED.store(true, Ordering::Release);
    }
}

/// Milestone-2 safe point: when the tick latched a reschedule, perform the
/// deferred switch **outside** IRQ context and return the replacement
/// frame. Returns `None` when no switch is due. m-privilege can call this
/// at the syscall/iret boundary without changing milestone-1 code.
pub fn take_resched_frame(frame: *mut InterruptFrame) -> Option<*mut InterruptFrame> {
    if NEED_RESCHED.load(Ordering::Acquire) {
        Some(schedule(frame))
    } else {
        None
    }
}

/// Enable/disable tick preemption (milestone 2) and its PID0 exemption.
pub fn set_active(active: bool) {
    SCHED_ACTIVE.store(active, Ordering::Release);
}

pub fn set_preempt_user_only(only: bool) {
    PREEMPT_USER_ONLY.store(only, Ordering::Release);
}

pub fn need_resched() -> bool {
    NEED_RESCHED.load(Ordering::Acquire)
}

pub fn current_pid() -> u32 {
    let _guard = IrqGuard::lock();
    sched_mut().current_pid
}

pub fn switch_count() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

/// Milestone-1 gate: RR must switch context at least twice between two
/// fake PCBs. Emits `SCHED_OK`, then [`reset`]s so PID0 is the sole running
/// context again (the shell remains the idle loop — `SHELL_OK` /
/// `KEYBOARD_OK` are untouched).
pub fn prove() {
    reset();
    let before = SWITCHES.load(Ordering::Relaxed);

    // Two opaque frame regions, carved from the test processes' own kernel
    // stacks. No `idt::Frame` field is read — layout-independent by design.
    let frame_idle = (kernel_stack_top(0) - 32) as *mut c_void;
    let frame_a = (kernel_stack_top(1) - 32) as *mut c_void;
    let frame_b = (kernel_stack_top(2) - 32) as *mut c_void;

    let pid_a = match spawn(0x1000, read_cr3()) {
        Some(pid) => pid,
        None => fatal("spawn A refused"),
    };
    let pid_b = match spawn(0x2000, read_cr3()) {
        Some(pid) => pid,
        None => fatal("spawn B refused"),
    };
    if !install_frame(pid_a, frame_a) || !install_frame(pid_b, frame_b) {
        fatal("install_frame refused");
    }
    {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        if let Some(p) = s.proc_mut(0) {
            p.saved_context = frame_idle;
        }
    }

    // PID0 → A → B → PID0: three switches, more than the required two.
    let r1 = schedule(frame_idle.cast::<InterruptFrame>());
    let r2 = schedule(frame_a.cast::<InterruptFrame>());
    let r3 = schedule(frame_b.cast::<InterruptFrame>());
    if r1 != frame_a.cast::<InterruptFrame>()
        || r2 != frame_b.cast::<InterruptFrame>()
        || r3 != frame_idle.cast::<InterruptFrame>()
    {
        fatal("RR returned the wrong frame");
    }
    if SWITCHES.load(Ordering::Relaxed).saturating_sub(before) < 2 {
        fatal("fewer than two context switches");
    }
    if current_pid() != 0 {
        fatal("PID0 did not resume as idle");
    }

    reset();
    serial_println!("SCHED_OK"); // machine-checked by `cargo xtask smoke`
}

fn fatal(why: &str) -> ! {
    serial_println!("FATAL: sched: {why}");
    crate::halt()
}
