//! Round-robin scheduler — milestone 2: cooperative switches on
//! `Yield`/`Exit` **plus** a preemptive PIT tick gated by [`SCHED_ACTIVE`] /
//! [`PREEMPT_USER_ONLY`].
//!
//! The tick never performs the switch from inside the IRQ handler. It
//! accounts the quantum, latches [`NEED_RESCHED`] and *returns the frame to
//! resume*; `isr_common` switches `rsp` to that frame in its asm epilogue,
//! after the Rust handler has returned. That is the safe point: no nested IRQ,
//! no `sti` from an interrupt context.
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
use crate::memory::{USER_BASE, USER_STACK_SIZE};
use crate::userland::process::{KERNEL_STACK_SIZE, MAX_FREE_FRAMES, MAX_PROCS, Process, State};
use crate::userland::userptr::{Vm, set_vm};
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// PIT is 100 Hz ([`crate::pit::HZ`]); 10 ticks = 100 ms quantum.
const QUANTUM_TICKS: u32 = 10;

/// 64-bit TSS descriptor in the GDT. m-privilege installs GDT6; before that
/// lands, `tss_rsp0_addr` returns `None` and the RSP0 write is skipped
/// (documented deviation, no effect on the milestone-1 proof).
const TSS_GDT_INDEX: usize = 5; // 0x28 / 8 = 5 (GDT6+TSS has 7 slots)
/// `RSP0` sits at byte offset 4 in the 64-bit TSS.
const TSS_RSP0_OFFSET: u64 = 4;

/// Conventional flat 64-bit user selectors. **m-privilege owns the GDT** —
/// if its user selectors differ, change these two constants there or here;
/// they are used only when synthesizing a brand-new CPL3 frame.
const USER_CS: u64 = 0x1b; // flat user code selector (GDT entry 3, DPL3) — m-privilege owns the GDT
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
/// PID0's original idle frame, copied out before the fault proof overwrites
/// the resume slot with `fault_proof_resume` (hito 2).
static mut SAVED_IDLE_FRAME: [u8; core::mem::size_of::<InterruptFrame>()] =
    [0; core::mem::size_of::<InterruptFrame>()];

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
    // Byte 5 of the 16-byte TSS descriptor is its access byte (0x8b
    // after `ltr`: present + busy); byte 6 is the limit/flags nibble
    // (0x00). With raw[6] the mask yields 0, tss_rsp0_addr returns
    // None and TSS.RSP0 is never updated on a switch — a child's
    // int 0x80 then overwrites the parent's saved resume frame.
    let access = raw[5];
    if !matches!(access & 0x0f, 0x09 | 0x0b) || access & 0x80 == 0 {
        return None;
    }
    let base = u64::from(raw[2])
        | (u64::from(raw[3]) << 8)
        | (u64::from(raw[4]) << 16)
        | (u64::from(raw[7]) << 24)
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
    // Publish the incoming process's VMAs before any of its syscalls can
    // touch a user pointer (hito 2 debt): with Vm::NONE every Write is
    // EFAULT. The ELF's PT_LOAD occupies the low user region, the stack
    // the top of USER_END (both bounded by userptr's own caps).
    if pid == 0 {
        set_vm(Vm::NONE);
    } else if let Some(stack_lo) = p.user_stack_top.checked_sub(USER_STACK_SIZE) {
        set_vm(Vm {
            brk_base: USER_BASE,
            brk_end: p.brk_end,
            stack_base: stack_lo,
            stack_end: p.user_stack_top,
        });
    }
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
        // Enter ring 3 with IF clear: the first user process performs a
        // single Write syscall and exits; no timer IRQ is needed, and a
        // pending IRQ delivered on the first iretq with a half-installed
        // user stack caused #GP on the live QEMU path. The syscall gate
        // re-enables IF on return via RFLAGS in the saved frame.
        core::ptr::write_unaligned(base.add(flags_off) as *mut u64, 0x2);
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
    // Seed PID0's FPU image from the live hardware state so every later
    // `fxrstor` has a valid (masked-exception) image to load.
    // SAFETY: `fpu.0` is 16-byte aligned and 512 writable bytes inside a
    // static PCB; single core, IF=0 (guard held), ring 0.
    unsafe { crate::idt::fxsave(s.procs[0].fpu.0.as_mut_ptr()) };
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
    // Hito 2: the PIT tick is a real preemption source from here on.
    // `pit::on_tick` still filters ring-0 frames (PREEMPT_USER_ONLY), so the
    // 30-marker boot chain is untouched until a CPL3 frame is interrupted.
    set_active(true);
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
    // The frame needs room for all 15 saved GPRs (120 B) + vector/error
    // (16 B) + RIP/CS/RFLAGS/RSP/SS (40 B) = 176 B, rounded up to 192 for
    // alignment. Placing it only 16 B below the stack top made the last
    // fields (`user_rsp`/`user_ss`) land ABOVE the 4 KiB stack — iretq
    // then read garbage and #GP'd. Keep the entire frame inside it.
    const FRAME_BYTES: u64 = 192;
    let frame = (top - FRAME_BYTES) as *mut c_void;
    // SAFETY: `top` is a 16-byte-aligned 4 KiB stack top and FRAME_BYTES
    // (192) exceeds the frame size (176), so every written field stays
    // inside this process's own kernel stack.
    unsafe { build_user_frame(frame, entry, user_stack_top) };
    let mut p = Process::new(pid, cr3_phys, top, entry, user_stack_top);
    // U2b: publish the ELF's data region as the initial `brk` VMA,
    // otherwise install_context() would overwrite it with 0 on each
    // switch and every user Write after a Yield would be EFAULT.
    // The loader maps the PT_LOAD at USER_BASE..USER_BASE+1 MiB; the
    // userptr caps bound it, so a coarse but honest end is fine here.
    p.brk_end = crate::memory::USER_BASE + (1 << 20);
    p.saved_context = frame;
    p.quantum_left = QUANTUM_TICKS;
    // Give the fresh PCB a valid FPU image (the outgoing kernel state) so
    // its first `fxrstor` cannot load an all-zero MXCSR with exceptions
    // unmasked.
    // SAFETY: `p.fpu.0` is 16-byte aligned and 512 writable bytes inside a
    // static PCB; single core, IF=0 (guard held), ring 0.
    unsafe { crate::idt::fxsave(p.fpu.0.as_mut_ptr()) };
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
            // Save x87/XMM/MXCSR into the outgoing PCB.
            // SAFETY: `fpu.0` is a 16-byte-aligned 512-byte buffer in the
            // static PCB array; single core, IF=0, ring 0 (fxsave writes
            // only that buffer and reads live FPU state).
            unsafe { crate::idt::fxsave(p.fpu.0.as_mut_ptr()) };
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
    // Restore the incoming task's x87/XMM/MXCSR image.
    // SAFETY: `fpu.0` is a 16-byte-aligned 512-byte image produced by a
    // matching `fxsave` (spawn/reset seed it from live state); single core,
    // IF=0, ring 0.
    if let Some(p) = s.proc(next_pid) {
        unsafe { crate::idt::fxrstor(p.fpu.0.as_ptr()) };
    }
    // `iretq` does not restore FS/GS. Clear any kernel TLS bases before
    // resuming a user context (CPL3 is identified by a non-zero entry;
    // reading the frame here would be unsafe for synthetic hito-1 frames).
    if s.proc(next_pid).is_some_and(|p| p.user_entry != 0) {
        crate::idt::clear_fs_gs();
    }

    SWITCHES.fetch_add(1, Ordering::Relaxed);
    NEED_RESCHED.store(false, Ordering::Release);

    // Snapshot the destination frame while the IrqGuard still holds IF=0.
    // Re-reading `p.saved_context` after the guard drops let a PIT tick
    // overwrite it with an IRQ frame, corrupting the resumed GPRs (hito 5
    // race: socket handle overwritten with "zo: mock" bytes).
    match s.proc(next_pid) {
        Some(p) if !p.saved_context.is_null() => p.saved_context.cast::<InterruptFrame>(),
        _ => frame,
    }
}

/// First-resume frame of a freshly spawned process (used by the boot
/// path to `iretq` into ring 3 for the first time).
///
/// Also installs the process as the scheduler's current context. The ELF
/// loader owns the page table but not `current_pid`, so without this the
/// first `Exit`/tick/fault would be charged to PID0 (hito 1's idle context).
pub fn first_frame(pid: u32) -> Option<*mut InterruptFrame> {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    let frame = s
        .proc(pid)
        .filter(|p| !p.saved_context.is_null())?
        .saved_context;
    s.current_pid = pid;
    if let Some(p) = s.proc_mut(pid) {
        p.state = State::Running;
        p.quantum_left = QUANTUM_TICKS;
    }
    Some(frame.cast::<InterruptFrame>())
}

/// Syscall entry for `Yield`: same switch, current stays runnable.
pub fn yield_current(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    schedule(frame)
}

/// Syscall entry for `Exit`: mark the current process dead, prove hito 2
/// (preemptive RR, `Yield`, user `#PF`) and hand control back to PID0.
///
/// The proofs run here because this is the one kernel point that is already
/// on the int 0x80 kernel stack with the staged user address space loaded:
/// no extra module or loader change is needed. The final fault proof uses a
/// real CPL3 `iretq` into an unmapped user RIP, so the #PF travels through
/// the real IDT path, and [`fault_proof_resume`] is the kernel resume point.
pub fn exit_current(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    let (pid, user_cr3, user_entry, user_stack, idle) = {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        let pid = s.current_pid;
        if let Some(p) = s.proc_mut(pid) {
            p.state = State::Exited;
        }
        let (cr3, entry, stack) = match s.proc(pid) {
            Some(p) => (p.cr3_phys, p.user_entry, p.user_stack_top),
            None => (0, 0, 0),
        };
        // PID0's resume slot is reused by `enter_user` for the fault proof;
        // preserve the original frame and its rip first.
        (pid, cr3, entry, stack, s.procs[0].saved_context)
    };
    let _ = (pid, frame); // the exiting frame stays on its own kernel stack

    if idle.is_null() || user_cr3 == 0 || user_entry == 0 {
        fatal("exit: no idle frame or user context");
    }
    // SAFETY: `idle` is a live 176-byte frame in PID0's kernel stack and
    // SAVED_IDLE_FRAME is a private 176-byte static; no alias, IF=0.
    unsafe {
        core::ptr::copy_nonoverlapping(
            idle as *const u8,
            core::ptr::addr_of_mut!(SAVED_IDLE_FRAME) as *mut u8,
            core::mem::size_of::<InterruptFrame>(),
        )
    };

    let (a, _b, b_frame) = prove_rr(user_cr3, user_entry, user_stack);
    prove_yield(b_frame, a);
    finish_proofs();

    // A second `iretq` into CPL3 — this time at an unmapped user RIP — makes
    // the CPU raise #PF through the real IDT gate. Reusing the staged ELF's
    // CR3 needs no new module or loader path.
    let fault_pid = match spawn_with_stack(
        crate::userland::elf::USER_BASE + 0x0800_0000,
        user_cr3,
        user_stack,
    ) {
        Some(p) => p,
        None => fatal("fault proof: no PCB"),
    };
    let fault_frame = match first_frame(fault_pid) {
        Some(f) => f,
        None => fatal("fault proof: no frame"),
    };
    let slot = match usize::try_from(fault_pid) {
        Ok(i) if i < MAX_PROCS => i,
        _ => fatal("fault proof: bad pid"),
    };
    {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        s.current_pid = fault_pid;
        if let Some(p) = s.proc_mut(fault_pid) {
            p.state = State::Running;
            p.quantum_left = QUANTUM_TICKS;
        }
    }
    // SAFETY: the frame was synthesized by `spawn_with_stack`; `user_cr3`
    // and the kernel stack come from the staged ELF's own PCB. Interrupts
    // are masked by the int 0x80 gate and this call never returns.
    unsafe {
        enter_user(
            fault_frame,
            user_cr3,
            kernel_stack_top(slot),
            fault_proof_resume as *const () as u64,
        )
    }
}

/// Round-robin proof: two synthetic CPL3 processes, `QUANTUM_TICKS` real
/// `on_tick` calls, one handoff. Returns `(first pid, second pid, second
/// frame)` for the yield proof that follows.
fn prove_rr(user_cr3: u64, user_entry: u64, user_stack: u64) -> (u32, u32, *mut InterruptFrame) {
    let a = match spawn_with_stack(user_entry, user_cr3, user_stack) {
        Some(p) => p,
        None => fatal("rr proof: no PCB for A"),
    };
    let b = match spawn_with_stack(user_entry, user_cr3, user_stack) {
        Some(p) => p,
        None => fatal("rr proof: no PCB for B"),
    };
    let a_frame = match first_frame(a) {
        Some(f) => f,
        None => fatal("rr proof: no frame for A"),
    };
    let b_frame = match first_frame(b) {
        Some(f) => f,
        None => fatal("rr proof: no frame for B"),
    };
    {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        s.current_pid = a;
        if let Some(p) = s.proc_mut(a) {
            p.state = State::Running;
            p.quantum_left = QUANTUM_TICKS;
        }
        if let Some(p) = s.proc_mut(b) {
            p.state = State::Ready;
            p.quantum_left = QUANTUM_TICKS;
        }
    }

    let before = switch_count();
    // First tick goes through the *registered* IDT hook (mod.rs →
    // sched::on_tick), proving that indirection is live too; the remaining
    // ticks call the scheduler entry directly so the returned frame is not
    // discarded by the adapter.
    let mut got = crate::idt::call_tick_hook(a_frame);
    for _ in 1..QUANTUM_TICKS {
        got = on_tick(a_frame);
    }
    if got != b_frame || current_pid() != b {
        fatal("rr: quantum did not hand off the next process");
    }
    if switch_count().saturating_sub(before) < 1 {
        fatal("rr: no context switch");
    }
    serial_println!("SCHED_RR_OK");
    (a, b, b_frame)
}

/// Yield proof: dispatch the real `NR_YIELD` syscall through the ABI and
/// assert the scheduler really handed the CPU to the other ready process.
fn prove_yield(from_frame: *mut InterruptFrame, expected: u32) {
    let before = switch_count();
    let next = {
        // SAFETY: `from_frame` is a 192-byte synthetic frame on a PCB-owned
        // kernel stack; only the kernel touches it while IF=0 here.
        let f = unsafe { &mut *from_frame };
        f.rax = crate::userland::syscall::NR_YIELD;
        crate::userland::syscall::dispatch_resume(f)
    };
    if next == from_frame || current_pid() != expected {
        fatal("yield: no handoff to the next process");
    }
    if switch_count().saturating_sub(before) < 1 {
        fatal("yield: no context switch");
    }
    serial_println!("USER_YIELD_OK");
}

/// Retire every proof process and reinstall PID0 as the sole running
/// context (kernel CR3 + RSP0), before the fault `iretq`.
fn finish_proofs() {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    for p in s.procs.iter_mut() {
        if p.pid != 0 && p.is_allocated() {
            p.state = State::Exited;
        }
    }
    s.current_pid = 0;
    if let Some(p) = s.proc_mut(0) {
        p.state = State::Running;
    }
    NEED_RESCHED.store(false, Ordering::Release);
    install_context(s, 0);
}

/// Kernel resume point after the proof process takes its CPL3 #PF.
/// Rebuild PID0's original frame (saved in `exit_current`) and iretq into
/// `load::idle_resume`, which prints the final marker and halts.
extern "C" fn fault_proof_resume() -> ! {
    let frame = {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        s.current_pid = 0;
        if let Some(p) = s.proc_mut(0) {
            p.state = State::Running;
        }
        NEED_RESCHED.store(false, Ordering::Release);
        install_context(s, 0); // kernel CR3 + RSP0 back
        s.procs[0].saved_context
    };
    if frame.is_null() {
        fatal("fault resume: no idle frame");
    }
    // Restore the copy captured before `enter_user` reused this slot. The
    // guard is already dropped, so nothing live sits in the frame region.
    // SAFETY: `frame` is PID0's 176-byte frame in its own kernel stack;
    // SAVED_IDLE_FRAME holds exactly that many bytes; single core, IF=0.
    unsafe {
        core::ptr::copy_nonoverlapping(
            core::ptr::addr_of!(SAVED_IDLE_FRAME) as *const u8,
            frame as *mut u8,
            core::mem::size_of::<InterruptFrame>(),
        )
    };
    // SAFETY: the frame was restored from a copy of a `save_idle_frame`
    // frame; it lies inside PID0's 4 KiB kernel stack and iretq consumes it
    // exactly once (ring-0 frame: no RSP/SS pop).
    unsafe { resume_frame(frame.cast::<InterruptFrame>()) }
}

/// Switch `rsp` to `frame` and `iretq`. CR3/RSP0 are already PID0's;
/// `enter_user` documents the same 136-byte skip to reach `rip`.
///
/// # Safety
/// `frame` must be a valid ring-0 `InterruptFrame` on a kernel stack that
/// remains mapped after the CR3 load. Called once, interrupts masked.
unsafe fn resume_frame(frame: *mut InterruptFrame) -> ! {
    // SAFETY: see above; iretq consumes the caller-provided frame once.
    unsafe {
        core::arch::asm!(
            "cli",
            "mov rsp, {frame}",
            "add rsp, 136",
            "iretq",
            frame = in(reg) frame,
            options(noreturn),
        );
    }
}

/// IRQ0 hook. **Exact signature required by m-privilege**: the frame
/// returned is the one `isr_common` resumes with.
///
/// Accounts the quantum, saves the interrupted frame and latches
/// [`NEED_RESCHED`] on expiry. The actual switch is consumed at the safe
/// point below — still this function's return value, but after the mutable
/// borrow of the scheduler has been dropped, so `isr_common` performs the
/// `rsp` swap in its epilogue once the Rust IRQ handler has returned. No IRQ
/// recursion, no `sti` from the guard, PID0 exempt when
/// [`PREEMPT_USER_ONLY`] is set.
pub fn on_tick(frame: *mut InterruptFrame) -> *mut InterruptFrame {
    {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        let pid = s.current_pid;
        if pid == 0 || !SCHED_ACTIVE.load(Ordering::Acquire) {
            return frame;
        }
        let Some(p) = s.proc_mut(pid) else {
            return frame;
        };
        // `PREEMPT_USER_ONLY` is true means PID0 is untouchable (already
        // covered by `pid == 0`). Exposed so the policy can be widened
        // without touching this function.
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
    // Safe point: `take_resched_frame` runs the real switch once the
    // scheduler borrow and the IF=0 guard are gone. The returned frame is
    // installed by the asm epilogue, not by this IRQ handler.
    take_resched_frame(frame).unwrap_or(frame)
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

/// A CPL3 #PF/#GP kills the offending process and returns PID0's frame.
///
/// The faulting frame is abandoned on the killed process's own kernel stack
/// (`idt::on_user_fault` passes it in from `CURRENT_FRAME`); the returned
/// frame is installed by `isr_common`. Frames recorded in the PCB are freed
/// here. The staged hello ELF's page table is deliberately **not** freed: it
/// is shared with the other PCBs of this proof, and only `LoadedProcess`
/// (load.rs) owns the handle needed for a full address-space teardown —
/// migrating that ownership into the PCB is hito 3 work.
pub fn on_user_fault(frame: *mut InterruptFrame, kind: &str) -> *mut InterruptFrame {
    let killed = {
        let _guard = IrqGuard::lock();
        let s = sched_mut();
        let pid = s.current_pid;
        if let Some(p) = s.proc_mut(pid) {
            let count = p.frame_count.min(MAX_FREE_FRAMES);
            for i in 0..count {
                if let Some(f) = crate::memory::Frame::from_phys(p.frames[i]) {
                    crate::memory::free(f);
                }
            }
            p.frames = [0; MAX_FREE_FRAMES];
            p.frame_count = 0;
            p.saved_context = core::ptr::null_mut();
            p.state = State::Exited;
        }
        pid
    };
    let _ = frame; // stays on the dead task's stack; never resumed
    serial_println!("sched: killed pid {killed} ({kind})");
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    s.current_pid = 0;
    if let Some(p) = s.proc_mut(0) {
        p.state = State::Running;
    }
    NEED_RESCHED.store(false, Ordering::Release);
    let idle = s.procs[0].saved_context;
    if idle.is_null() {
        fatal("user fault: no idle frame saved");
    }
    serial_println!("USER_FAULT_OK"); // killed pid {killed} by {kind}
    idle.cast::<InterruptFrame>()
}

/// Save a ring-0 frame for PID0 so a user `exit` can `iretq` back to
/// the point right after the jump. `rip` is the kernel resume address;
/// RSP0 is PID0's own kernel stack (the current one).
pub fn save_idle_frame(rip: u64) {
    let _guard = IrqGuard::lock();
    let s = sched_mut();
    let frame = s.procs[0].kernel_stack_top.saturating_sub(192) as *mut InterruptFrame;
    // SAFETY: the frame lies inside PID0's 4 KiB kernel stack; all fields
    // are written within its 176-byte layout. Slots beyond `rip`/`cs` are
    // zeroed so iretq ignores them (CS RPL=0 -> no RSP/SS pop).
    unsafe {
        core::ptr::write_bytes(frame as *mut u8, 0, 176);
        let base = frame as *mut u8;
        core::ptr::write_unaligned(
            base.add(core::mem::offset_of!(InterruptFrame, rip)) as *mut u64,
            rip,
        );
        core::ptr::write_unaligned(
            base.add(core::mem::offset_of!(InterruptFrame, cs)) as *mut u64,
            0x08,
        );
    }
    s.procs[0].saved_context = frame.cast::<c_void>();
    crate::idt::set_tss_rsp0(s.procs[0].kernel_stack_top);
}

/// Enter a freshly spawned user process for the first time (milestone 1).
///
/// The synthetic frame was built by `spawn_with_stack` on the process's
/// own kernel stack. We switch to that stack, load its CR3, point TSS.RSP0
/// at it (so a later `int 0x80` lands there), and execute `iretq` — the
/// CPU pops RIP/CS/RFLAGS and, because CS.RPL=3, RSP/SS from the frame.
/// This never returns: the process runs until `Exit`/`Yield`/a fault.
///
/// # Safety
/// `frame` must be a valid `InterruptFrame` synthesized by
/// `build_user_frame`, on a kernel stack that stays mapped in the new
/// CR3's identity half. `rsp0` must be that stack's top. Called once,
/// from the boot path with interrupts masked.
pub unsafe fn enter_user(
    frame: *mut InterruptFrame,
    cr3_phys: u64,
    rsp0: u64,
    resume_rip: u64,
) -> ! {
    // PID0 resumes at the caller-provided address (computed in load.rs
    // right after the call site). `Location::address()` is unstable on
    // this pinned toolchain, so the caller passes it explicitly.
    save_idle_frame(resume_rip);
    crate::idt::set_tss_rsp0(rsp0);
    crate::idt::clear_fs_gs();
    // SAFETY: single-core boot, IF masked by the caller; the frame and
    // the identity map are owned by this process and stay valid across
    // the switch. `iretq` consumes the frame exactly once.
    unsafe {
        core::arch::asm!(
            "cli",
            "mov cr3, {cr3}",
            "mov rsp, {frame}",
            // The frame pointer points at saved r15 (offset 0). iretq
            // expects RIP at rsp: skip 15 saved GPRs (120 B) + the dummy
            // vector/error words (16 B) = 136 bytes. Skipping only 16
            // made iretq read r13 as RIP -> #GP before reaching ring 3.
            "add rsp, 136",
            "iretq",
            cr3 = in(reg) cr3_phys,
            frame = in(reg) frame,
            options(noreturn),
        );
    }
}

fn fatal(why: &str) -> ! {
    serial_println!("FATAL: sched: {why}");
    crate::halt()
}
