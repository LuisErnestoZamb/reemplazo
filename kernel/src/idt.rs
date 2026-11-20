//! Interrupt Descriptor Table: build it from the asm stubs, load it with
//! `lidt`, and dispatch exceptions/IRQs to Rust.
//!
//! Layout contract: `isr_common` (interrupts.S) pushes [vector][error] then
//! all GPRs, so [`Frame`] mirrors that byte-for-byte (`#[repr(C)]`, lowest
//! address first).

use core::arch::global_asm;
use core::cell::UnsafeCell;

global_asm!(include_str!("interrupts.S"), options(att_syntax));

/// Code selector of the GDT64 built in `entry.S` (index 1 → 0x08).
const CODE_SELECTOR: u16 = 0x08;
/// 64-bit interrupt gate, present, DPL 0 (SDM Vol.3A §6.11.1.2).
const INTERRUPT_GATE: u8 = 0x8E;
/// Stub table: vectors 0..=47 plus the shared fallback at index 48.
const STUB_COUNT: usize = 49;

/// Register frame saved by `isr_common`, lowest address first.
#[repr(C)]
#[allow(dead_code)] // GPRs kept for future context switches/debugging.
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
        self.offset_low = handler as u16;
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.selector = CODE_SELECTOR;
        self.ist = 0;
        self.type_attr = INTERRUPT_GATE;
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
}

/// Build the IDT from `isr_stub_table` and load it. Must run before `sti`
/// (and before any exception other than the ones GRUB already set up).
pub fn init() {
    // SAFETY: `isr_stub_table` is a link-time constant emitted by
    // interrupts.S; STUB_COUNT bounds the copy.
    let stubs = unsafe { core::ptr::addr_of!(isr_stub_table).read() };

    // SAFETY: single write with interrupts disabled; see `Idt`.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, entry) in idt.iter_mut().enumerate() {
        // Vectors 0..=47 get their stub; everything else the fallback.
        let stub = stubs.get(vector).copied().unwrap_or(stubs[STUB_COUNT - 1]);
        entry.set_handler(stub);
    }

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

/// Top-level dispatcher called from `isr_common` (interrupts.S).
///
/// # Safety
/// `frame` must point to the valid [`Frame`] the asm prologue built on the
/// interrupt stack; the signature mirrors that contract (extern "C", called
/// once per interrupt, single-core).
#[unsafe(no_mangle)]
pub extern "C" fn interrupt_dispatch(frame: *mut Frame) {
    // SAFETY: contract of this function — pointer from our own asm stub,
    // valid for the duration of the call, no aliasing (single core).
    let frame = unsafe { &mut *frame };

    match frame.vector {
        // --- exceptions we handle and resume from ---
        3 => {
            serial_println!("EXC: breakpoint at rip={:#x} — resumed cleanly", frame.rip);
        }
        // --- fatal exceptions: dump and park (never resume) ---
        vector @ 0..=31 => {
            let cr2: u64 = if vector == 14 {
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
            } else {
                0
            };
            serial_println!(
                "FATAL: exception {vector} err={:#x} rip={:#x} cr2={:#x}",
                frame.error,
                frame.rip,
                cr2
            );
            crate::halt();
        }
        // --- hardware IRQs (PIC remapped to 32..=47) ---
        32 => {
            // PIT timer: account the tick, then EOI so IRQ0 can fire again.
            crate::pit::tick();
            crate::pic::eoi(0);
        }
        vector @ 33..=47 => {
            serial_println!("EXC: unexpected IRQ {vector} (all but IRQ0 masked)");
            crate::pic::eoi((vector - 32) as u8);
        }
        // --- shared fallback for vectors >= 48 (sentinel 0xFFFF) ---
        _ => {
            serial_println!(
                "FATAL: unexpected interrupt, err={:#x} rip={:#x}",
                frame.error,
                frame.rip
            );
            crate::halt();
        }
    }
}
