//! Interrupt Descriptor Table: build it from the asm stubs, load it with
//! `lidt`, and dispatch exceptions/IRQs to Rust.
//!
//! Layout contract: `isr_common` (interrupts.S) pushes [vector][error] then
//! all GPRs, so [`Frame`] mirrors that byte-for-byte (`#[repr(C)]`, lowest
//! address first). A CPL3→CPL0 entry makes the CPU push SS/RSP/RFLAGS/CS/RIP;
//! the two extra words (`user_rsp`/`user_ss`) therefore exist only in user
//! frames, and `iretq` reads them only when the saved CS has RPL=3.
//!
//! `interrupts.S` resumes whichever [`Frame`] the dispatcher returns. That is
//! the context-switch seam: the ordinary path returns the incoming frame,
//! the scheduler hook may return a different task's frame instead (see
//! [`register_sched_hooks`]).

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

global_asm!(include_str!("interrupts.S"), options(att_syntax));

/// Code selector of the GDT64 built in `entry.S` (index 1 → 0x08).
const CODE_SELECTOR: u16 = 0x08;
/// 64-bit interrupt gate, present, DPL 0 (SDM Vol.3A §6.11.1.2).
const INTERRUPT_GATE: u8 = 0x8E;
/// As above but DPL 3: user software may execute `int 0x80`. The gate's
/// target is still the ring-0 code selector 0x08; DPL only gates *entry*.
const USER_INTERRUPT_GATE: u8 = 0xEE;
/// Stub table has one slot per vector 0..=128 (index 128 is `int 0x80`).
const STUB_COUNT: usize = 129;
const USER_VECTOR: usize = 0x80;

/// Register frame saved by `isr_common`, lowest address first. The trailing
/// `user_rsp`/`user_ss` pair is present only when the interrupted context
/// was CPL3 (the CPU pushed them during the privilege switch).
#[repr(C)]
#[allow(dead_code)] // GPRs kept for context switches/debugging; user_* by iretq.
pub struct Frame {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub user_rsp: u64, // CPL3 only — read by `iretq`, never by Rust
    pub user_ss: u64,  // CPL3 only — read by `iretq`, never by Rust
}

/// One 16-byte IDT gate descriptor (SDM Vol.3A §6.11).
#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // read by the CPU via `lidt`, not by Rust.
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8, // bits 0..2 = IST index, 3..7 must be 0
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    fn set_handler(&mut self, handler: usize) {
        self.set_gate(handler, INTERRUPT_GATE);
    }

    fn set_user_handler(&mut self, handler: usize) {
        self.set_gate(handler, USER_INTERRUPT_GATE);
    }

    fn set_gate(&mut self, handler: usize, type_attr: u8) {
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = CODE_SELECTOR;
        self.ist = 0;
        self.type_attr = type_attr;
        self.reserved = 0;
    }
}

/// 256-entry IDT. Interior mutability instead of `static mut`: written once
/// in [`init`] with interrupts still disabled (single-core boot), then
/// read-only by the CPU.
struct Idt(UnsafeCell<[IdtEntry; 256]>);

// SAFETY: the cell is written only inside `init()`, which runs before
// `sti` on a single core; afterwards no Rust code mutates it.
unsafe impl Sync for Idt {}

static IDT: Idt = Idt(UnsafeCell::new([IdtEntry::missing(); 256]));

unsafe extern "C" {
    static isr_stub_table: [usize; STUB_COUNT];
    fn isr_unexpected();
}

/// Build the IDT from `isr_stub_table` and load it. Must run before `sti`
/// (and before any exception other than the ones GRUB already set up).
pub fn init() {
    // SAFETY: `isr_stub_table` is a link-time constant emitted by
    // interrupts.S; STUB_COUNT bounds the copy.
    let stubs = unsafe { core::ptr::addr_of!(isr_stub_table).read() };
    // Vector 0x80 is the only DPL3 gate; everything >= 129 keeps the
    // shared fallback (its stub pushes the 0xFFFF sentinel).
    let fallback = isr_unexpected as *const () as usize;

    // SAFETY: single write with interrupts disabled; see `Idt`.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, entry) in idt.iter_mut().enumerate() {
        let stub = if vector < STUB_COUNT {
            stubs[vector]
        } else {
            fallback
        };
        entry.set_handler(stub);
    }
    idt[USER_VECTOR].set_user_handler(stubs[USER_VECTOR]);

    let ptr = DescriptorTablePointer {
        limit: (256 * core::mem::size_of::<IdtEntry>() - 1) as u16,
        base: idt.as_ptr() as u64,
    };
    // SAFETY: `ptr` points at the static IDT (limit covers all 256 gates);
    // `lidt` only reads it.
    unsafe {
        core::arch::asm!(
            "lidt [{}]",
            in(reg) &ptr,
            options(readonly, nostack, preserves_flags)
        );
    }
}

/// Operand of `lidt`/`lgdt`: 2-byte limit + 8-byte base (SDM Vol.3A §3.5.1).
#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

// --- Scheduler seam -------------------------------------------------------
//
// The scheduler lives in a different milestone/module. These hooks keep this
// file (and the IRQ0 / user-fault paths) independent of it: the integrator
// registers `crate::userland::sched::on_tick` and its fault handler here once
// user tasks exist. Until then the frame returned is the incoming one.

/// Called by the scheduler once user tasks are runnable. Also safe to toggle
/// by hand; the tick hook below is a no-op while this is false.
pub static SCHED_ACTIVE: AtomicBool = AtomicBool::new(false);

/// `fn(*mut Frame) -> *mut Frame`: returns the frame to resume with.
pub type TickHook = fn(*mut Frame) -> *mut Frame;
/// `fn(*mut Frame, &str) -> *mut Frame`: kill the current user task and
/// return the next runnable frame. `kind` is `"page_fault"` or
/// `"general_protection"`.
pub type FaultHook = fn(*mut Frame, &str) -> *mut Frame;

/// `fn(*mut Frame) -> *mut Frame`: handles `int 0x80` and returns the
/// frame to resume (the same one if the syscall was handled in place).
pub type SyscallHook = fn(*mut Frame) -> *mut Frame;

static TICK_HOOK: AtomicUsize = AtomicUsize::new(0);
static FAULT_HOOK: AtomicUsize = AtomicUsize::new(0);
static SYSCALL_HOOK: AtomicUsize = AtomicUsize::new(0);
static CURRENT_FRAME: AtomicUsize = AtomicUsize::new(0);

/// Register the scheduler callbacks and enable preemption hooks.
#[allow(dead_code)] // connected by the scheduler milestone, not by boot.
pub fn register_sched_hooks(tick: TickHook, fault: FaultHook) {
    TICK_HOOK.store(tick as usize, Ordering::Release);
    FAULT_HOOK.store(fault as usize, Ordering::Release);
    SCHED_ACTIVE.store(true, Ordering::Release);
}

/// Register the syscall dispatcher behind `int 0x80` (DPL3 gate).
#[allow(dead_code)] // connected by the syscall-ABI milestone, not by boot.
pub fn register_syscall_hook(hook: SyscallHook) {
    SYSCALL_HOOK.store(hook as usize, Ordering::Release);
}

/// Indirect call used by `pit::on_tick` (which applies PREEMPT_USER_ONLY).
pub fn call_tick_hook(frame: *mut Frame) -> *mut Frame {
    let hook = TICK_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        return frame;
    }
    // SAFETY: written only by `register_sched_hooks` with this signature;
    // `usize` and `fn` pointers are both 8 bytes on x86-64, and the call
    // happens on the single boot CPU with interrupts masked by the gate.
    let f: TickHook = unsafe { core::mem::transmute::<usize, TickHook>(hook) };
    f(frame)
}

/// User-mode #PF/#GP entry point. The scheduler connects its task-kill path
/// through [`register_sched_hooks`]; with no hook registered there is no user
/// task to kill, so the incoming frame is returned unchanged (bring-up).
///
/// Never halts: a bad user program must not take the kernel down.
pub fn on_user_fault(kind: &str) -> *mut Frame {
    let frame = CURRENT_FRAME.load(Ordering::Relaxed) as *mut Frame;
    let hook = FAULT_HOOK.load(Ordering::Acquire);
    if hook == 0 {
        serial_println!("USER_FAULT: {kind} — no scheduler hook, resuming");
        return frame;
    }
    // SAFETY: see `call_tick_hook`; the fault hook gets the frame saved by
    // our asm stub and may mutate it / switch to another task's frame.
    let f: FaultHook = unsafe { core::mem::transmute::<usize, FaultHook>(hook) };
    f(frame, kind)
}

/// Point TSS.RSP0 at a task's kernel stack. A CPL3→CPL0 interrupt pushes
/// SS/RSP/RFLAGS/CS/RIP there; the TSS lives in `entry.S`.
#[allow(dead_code)] // called by the scheduler milestone, not by boot.
pub fn set_tss_rsp0(rsp: u64) {
    #[allow(dead_code)] // read via `addr_of!` below.
    unsafe extern "C" {
        static tss: [u8; 104];
    }
    // SAFETY: `tss` is our 104-byte, 16-byte-aligned static; offset 4 holds
    // an 8-byte RSP0 (written unaligned because +4 is only 4-byte aligned).
    // Single core, called before entering user mode or from the scheduler
    // with interrupts masked.
    unsafe {
        let base = core::ptr::addr_of!(tss) as *mut u8;
        core::ptr::write_unaligned(base.add(4) as *mut u64, rsp);
    }
}

// --- XMM / FS / GS state helpers (used by the scheduler per PCB) ----------
//
// Merom is x86-64-v1 but still executes SSE/XMM instructions (SSSE3 ceiling),
// so the FPU state must be saved/restored on every user↔kernel switch.

/// Size of the `fxsave`/`fxrstor` image in bytes.
#[allow(dead_code)] // used by the scheduler milestone's per-PCB FPU save.
pub const FXSAVE_SIZE: usize = 512;

/// Save x87 + XMM + MXCSR state into `dst`.
///
/// # Safety
/// `dst` must be non-null, 16-byte aligned and writable for [`FXSAVE_SIZE`]
/// bytes; the caller must be in ring 0 on the single boot CPU.
#[allow(dead_code)] // used by the scheduler milestone's per-PCB FPU save.
pub unsafe fn fxsave(dst: *mut u8) {
    // SAFETY: preconditions are the caller's contract above; `fxsave` only
    // reads the saved state and writes that buffer (no stack use).
    unsafe {
        core::arch::asm!("fxsave [{}]", in(reg) dst, options(nostack));
    }
}

/// Restore x87 + XMM + MXCSR state from `src`.
///
/// # Safety
/// Same preconditions as [`fxsave`], with a readable 512-byte image produced
/// by a matching `fxsave` (possibly from another task).
#[allow(dead_code)] // used by the scheduler milestone's per-PCB FPU restore.
pub unsafe fn fxrstor(src: *const u8) {
    // SAFETY: see above; `fxrstor` reads only the 512-byte image.
    unsafe {
        core::arch::asm!("fxrstor [{}]", in(reg) src, options(nostack));
    }
}

/// Zero the FS/GS linear bases before entering CPL3.
///
/// `iretq` does not restore FS/GS, so a kernel TLS value would otherwise
/// leak into user code. In long mode the base lives in MSRs, not in the
/// descriptor cache, hence `wrmsr`. The selector values stay at 0x10,
/// which is inert for addressing in long mode; the scheduler may zero
/// them too if a future milestone uses FS for user TLS.
#[allow(dead_code)] // called by the scheduler milestone before user entry.
pub fn clear_fs_gs() {
    // SAFETY: `wrmsr` is ring-0 only; the kernel is the sole caller and it
    // runs on one CPU with interrupts masked by the gate. ECX/EAX/EDX are
    // explicitly listed as inputs so the compiler cannot reuse stale values.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0100u32, // FS.base
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags)
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") 0xC000_0101u32, // GS.base
            in("eax") 0u32,
            in("edx") 0u32,
            options(nostack, preserves_flags)
        );
    }
}

/// Read CR2 (faulting linear address for #PF).
fn cr2() -> u64 {
    // SAFETY: reading CR2 is always legal in ring 0.
    let v: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, cr2",
            out(reg) v,
            options(nomem, nostack, preserves_flags)
        );
    }
    v
}

/// Top-level dispatcher called from `isr_common` (interrupts.S).
///
/// Returns the frame the asm epilogue must resume. The caller switches `rsp`
/// to it before popping the GPRs, so returning another task's frame is the
/// whole context switch.
///
/// # Safety
/// `frame` must point to the valid [`Frame`] the asm prologue built on the
/// interrupt stack; the signature mirrors that contract (extern "C", called
/// once per interrupt, single-core).
#[unsafe(no_mangle)]
pub extern "C" fn interrupt_dispatch(frame: *mut Frame) -> *mut Frame {
    // Save/restore so a nested IRQ (IF is masked by the gate, but kernel
    // code may `sti`) cannot leave `on_user_fault` with a stale frame.
    let previous = CURRENT_FRAME.load(Ordering::Relaxed);
    CURRENT_FRAME.store(frame as usize, Ordering::Relaxed);
    // Copy the fields we need into locals: hooks may mutate the frame
    // through the raw pointer while we decide what to return.
    let (vector, cs, rip, error) = {
        // SAFETY: contract of this function — pointer from our own asm stub,
        // valid for the duration of the call, no aliasing (single core).
        let f = unsafe { &*frame };
        (f.vector, f.cs, f.rip, f.error)
    };
    let fault_addr = if vector == 14 { cr2() } else { 0 };

    let next = match vector {
        // --- exceptions we handle and resume from ---
        3 => {
            serial_println!("EXC: breakpoint at rip={:#x} — resumed cleanly", rip);
            None
        }
        // --- user faults: kill the task, return to the scheduler ---
        vector @ 13 | vector @ 14 if cs & 3 == 3 => {
            let kind = if vector == 14 {
                "page_fault"
            } else {
                "general_protection"
            };
            serial_println!(
                "USER_FAULT: {kind} at rip={:#x} err={:#x} cr2={:#x} — killing task",
                rip,
                error,
                fault_addr
            );
            Some(on_user_fault(kind))
        }
        // --- fatal ring-0 exceptions: dump and park (never resume) ---
        vector @ 0..=31 => {
            serial_println!(
                "FATAL: exception {vector} err={:#x} rip={:#x} cr2={:#x}",
                error,
                rip,
                fault_addr
            );
            crate::halt();
        }
        // --- hardware IRQs (PIC remapped to 32..=47) ---
        32 => {
            // PIT timer: account the tick, EOI so IRQ0 can fire again.
            crate::pit::tick();
            crate::pic::eoi(0);
            Some(crate::pit::on_tick(frame))
        }
        vector @ 33..=47 => {
            serial_println!("EXC: unexpected IRQ {vector} (all but IRQ0 masked)");
            crate::pic::eoi((vector - 32) as u8);
            None
        }
        128 => {
            // int 0x80: the syscall ABI dispatcher is connected by the
            // integrator; with no hook the frame is resumed unchanged.
            let hook = SYSCALL_HOOK.load(Ordering::Acquire);
            if hook == 0 {
                serial_println!("EXC: int 0x80 with no syscall handler — resumed");
                None
            } else {
                // SAFETY: written only by `register_syscall_hook` with this
                // signature; the hook runs on one CPU with IF masked.
                let f: SyscallHook = unsafe { core::mem::transmute::<usize, SyscallHook>(hook) };
                Some(f(frame))
            }
        }
        // --- shared fallback for vectors >= 129 (sentinel 0xFFFF) ---
        _ => {
            serial_println!(
                "FATAL: unexpected interrupt, err={:#x} rip={:#x}",
                error,
                rip
            );
            crate::halt();
        }
    };

    CURRENT_FRAME.store(previous, Ordering::Relaxed);
    next.unwrap_or(frame)
}
