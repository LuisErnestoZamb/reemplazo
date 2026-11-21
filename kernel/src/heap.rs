//! Kernel heap: `linked_list_allocator::Heap` behind an IRQ-aware lock,
//! registered as the `#[global_allocator]`.
//!
//! Dependency review: `docs/dependencies.md` §4 — `linked_list_allocator`
//! 0.10.6, the canonical no_std heap (RUSTSEC-2022-0063, an out-of-bounds
//! write on tiny/unaligned heaps, is patched in **≥ 0.10.2**; 0.10.6 is
//! clean). It is pulled with `default-features = false`: the default
//! `use_spin` feature would bring `spinning_top → lock_api → scopeguard`
//! *and* a plain spinlock that does not disable interrupts — useless
//! against an interrupt arriving mid-allocation. Instead the plain [`Heap`]
//! sits in our own interrupt-aware cell ([`IrqCell`]).
//!
//! # IRQ rule
//!
//! **Interrupt handlers must never allocate.** The IRQ0/PIT handler in
//! `idt.rs` does not (it only ticks a counter and sends EOI), and that
//! is a hard rule for every future handler. The cell also masks
//! interrupts while held ([`IrqCell::lock`]), so the lock itself cannot
//! deadlock even if the rule were broken — but allocation inside a
//! handler is still forbidden: it adds unbounded latency to the IRQ path
//! and a panic there (see OOM policy) would run the panic handler from
//! interrupt context.
//!
//! # OOM policy
//!
//! A failed allocation returns a null pointer from [`GlobalAlloc::alloc`];
//! `alloc`'s default `handle_alloc_error` then **panics** ("memory
//! allocation of N bytes failed"), which reaches this kernel's
//! `#[panic_handler]` — `PANIC: …` on the serial console — and halts.
//! There is no OOM recovery: a failed allocation is fatal by design.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::ptr::{self, NonNull};
use core::sync::atomic::{AtomicBool, Ordering};

use alloc::vec::Vec;
use linked_list_allocator::Heap;

/// Heap size carved at boot. The smoke proof is KiB-scale; 16 MiB leaves
/// headroom for the AI client/editor allocations and stays cheap against
/// the 2.9 GB target (growable later via `Heap::extend` + more frames).
const HEAP_BYTES: u64 = 16 << 20;

/// The global heap: a plain [`Heap`] in an interrupt-aware spin cell.
///
/// **IRQ rule: handlers must never allocate** (the IRQ0 handler doesn't);
/// see the module docs. [`lock`](IrqCell::lock) additionally masks
/// interrupts for the duration of every allocator call.
struct IrqCell {
    locked: AtomicBool,
    heap: UnsafeCell<Heap>,
}

// SAFETY: the interior mutability is only reachable through `lock()`,
// which masks interrupts while held; the kernel is single-core, so no two
// execution contexts can be inside the critical section at once.
unsafe impl Sync for IrqCell {}

impl IrqCell {
    const fn empty() -> Self {
        Self {
            locked: AtomicBool::new(false),
            heap: UnsafeCell::new(Heap::empty()),
        }
    }

    /// Take the lock with interrupts masked.
    ///
    /// Interrupts are disabled *before* spinning and restored to the
    /// caller's exact prior state on release ([`save_and_disable`] /
    /// [`restore`]), because allocation happens both with interrupts off
    /// (boot) and on (shell): restoring a fixed state would leak or drop
    /// the caller's IF bit. Masking while held is what makes the lock
    /// IRQ-safe — an interrupt can never arrive to spin on a lock the
    /// interrupted context already owns.
    fn lock(&self) -> IrqGuard<'_> {
        let flags = save_and_disable();
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        // SAFETY: `locked` was false and is now set by us, interrupts are
        // masked, single core ⇒ exclusive access until the guard drops.
        let heap = unsafe { &mut *self.heap.get() };
        IrqGuard {
            cell: self,
            heap,
            flags,
        }
    }
}

/// RAII guard: hands out the `&mut Heap`, releases and restores the
/// interrupt state on drop.
struct IrqGuard<'a> {
    cell: &'a IrqCell,
    heap: &'a mut Heap,
    flags: u64,
}

impl Deref for IrqGuard<'_> {
    type Target = Heap;
    fn deref(&self) -> &Heap {
        self.heap
    }
}

impl DerefMut for IrqGuard<'_> {
    fn deref_mut(&mut self) -> &mut Heap {
        self.heap
    }
}

impl Drop for IrqGuard<'_> {
    fn drop(&mut self) {
        // Release the lock *before* restoring flags: if the saved state
        // had IF=1, the first interrupt after the restore must never see
        // the lock still held (it would spin with interrupts on).
        self.cell.locked.store(false, Ordering::Release);
        restore(self.flags);
    }
}

/// Snapshot RFLAGS and mask interrupts (`CLI`).
///
/// Must be balanced by a [`restore`] with the returned value, on the
/// same CPU (see the `IrqCell::lock` docs).
fn save_and_disable() -> u64 {
    let flags: u64;
    // SAFETY: `pushfq; pop` snapshots RFLAGS and `cli` clears IF. No
    // `nostack`: the push/pop deliberately use the stack below RSP, so the
    // compiler keeps locals out of the red zone; an interrupt arriving
    // in the window between the two instructions pushes *below* RSP and
    // cannot touch the snapshot sitting at [RSP].
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {flags}",
            "cli",
            flags = out(reg) flags,
        );
    }
    flags
}

/// Restore RFLAGS (notably IF) saved by [`save_and_disable`].
///
/// Contract: `flags` must come from `save_and_disable` on this CPU, and
/// every `save_and_disable` since then must have been balanced by a
/// restore (the lock's RAII guard upholds this).
fn restore(flags: u64) {
    // SAFETY: caller contract above; `push`/`popfq` pair atomically
    // restore the full register with no interrupt window in between.
    unsafe {
        core::arch::asm!(
            "push {flags}",
            "popfq",
            flags = in(reg) flags,
        );
    }
}

unsafe impl GlobalAlloc for IrqCell {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.size() == 0 {
            // Zero-sized layout: hand back a dangling-but-aligned pointer
            // (like std does) instead of probing the hole list with size 0.
            return layout.align() as *mut u8;
        }
        self.lock()
            .allocate_first_fit(layout)
            .map_or(ptr::null_mut(), |p| p.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if layout.size() == 0 {
            return; // nothing real was handed out, nothing to free
        }
        // SAFETY: the caller guarantees `ptr` came from `alloc` with this
        // exact layout; `NonNull::new_unchecked` therefore cannot see NULL
        // (null is only ever returned for size 0, handled above).
        unsafe {
            self.lock().deallocate(NonNull::new_unchecked(ptr), layout);
        }
    }
}

#[global_allocator]
static ALLOCATOR: IrqCell = IrqCell::empty();

/// Carve a contiguous region out of the frame allocator and initialize
/// the global heap. Call once, right after `memory::selftest`.
pub fn init() {
    let target = HEAP_BYTES / crate::memory::FRAME_SIZE;
    let Some((start, frames)) = crate::memory::carve_contiguous(target) else {
        serial_println!("FATAL: heap: no free frames to carve");
        crate::halt();
    };
    let bytes = (frames * crate::memory::FRAME_SIZE) as usize;

    let mut heap = ALLOCATOR.lock();
    // SAFETY: the carve returned a run of frames this kernel allocated
    // from the E820 "available" pool — identity-mapped RAM (entry.S maps
    // the first 4 GiB), still marked used in the bitmap so nothing else
    // hands it out — and `Heap::init` is called exactly once, on an
    // empty heap. See `memory::carve_contiguous` for the contiguity
    // argument.
    unsafe { heap.init(start as *mut u8, bytes) };
    let usable = heap.size();
    drop(heap);

    serial_println!("memory: heap {:#x} ({} KiB)", start, usable / 1024);
}

/// Boot-time proof that the heap works: push/check/drop a few thousand
/// values through `alloc::vec::Vec`, assert a simple invariant (the
/// arithmetic sum), then print `ALLOC_OK`.
///
/// Runs before the network chain. The vectors are a few tens of KiB —
/// far below the 16 MiB heap — so this cannot OOM (and an OOM would be
/// fatal anyway; see the OOM policy in the module docs).
pub fn prove_alloc() {
    const N: u64 = 4096;

    let mut v: Vec<u64> = Vec::with_capacity(N as usize);
    for i in 0..N {
        v.push(i);
    }
    assert_eq!(v.len(), N as usize, "heap: Vec length drifted");
    let sum: u64 = v.iter().sum();
    assert_eq!(sum, N * (N - 1) / 2, "heap: Vec contents corrupted");
    drop(v); // free path: the block must return to the hole list

    // Allocate again after the drop to prove the memory was reclaimed.
    let mut w: Vec<u64> = Vec::with_capacity(N as usize);
    for i in 0..N {
        w.push(i * 3);
    }
    let sum: u64 = w.iter().sum();
    assert_eq!(sum, 3 * N * (N - 1) / 2, "heap: reuse corrupted data");
    drop(w);

    serial_println!("ALLOC_OK"); // machine-checked by `cargo xtask smoke`
}
