//! Physical frame allocator: bitmap over the Multiboot2 memory map.
//!
//! Design notes:
//! - Bitmap is `[AtomicU64; N]`, not `static mut` (project rule); atomics
//!   also make `alloc` safe if an IRQ handler ever races the boot code.
//! - Bits start as *used*; [`init`] frees the bootloader's available
//!   regions, then re-reserves what the spec §3.6.8 says is listed as
//!   available anyway: kernel image, mbi, and low conventional memory.
//! - Frames are 4 KiB; tracked space is 4 GiB because `entry.S` only
//!   identity-maps the first 4 GiB (regions beyond that are ignored).

use core::sync::atomic::{AtomicU64, Ordering};
use multiboot2::{BootInformation, MemoryAreaType};

/// Frame size in bytes (x86-64 standard page).
pub const FRAME_SIZE: u64 = 4096;
/// Physical bytes trackable by this allocator (matches the identity map).
const TRACKED_BYTES: u64 = 4 << 30;
const TOTAL_FRAMES: u64 = TRACKED_BYTES / FRAME_SIZE;
const WORD_COUNT: usize = (TOTAL_FRAMES / 64) as usize; // 128 KiB bitmap

/// 1 = used/reserved, 0 = free. Inline `const` block (not a named const:
/// clippy rejects consts with interior mutability) for the array repeat.
/// Initialized to "all used"; [`init`] frees the available regions.
static BITMAP: [AtomicU64; WORD_COUNT] = [const { AtomicU64::new(u64::MAX) }; WORD_COUNT];

/// A 4 KiB physical frame, identified by frame number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame(u64);

impl Frame {
    /// Physical address of the frame's first byte.
    pub fn start_phys(self) -> u64 {
        self.0 * FRAME_SIZE
    }
}

/// Free every frame inside the bootloader's available regions, then reserve
/// what Multiboot2 §3.6.8 guarantees is *also* listed as available: the
/// kernel image (incl. `.bss`: stack, page tables, this bitmap) and the mbi
/// structure. Low memory (< 1 MiB) is reserved conservatively.
///
/// Call once, before handing frames out. Idempotent.
pub fn init(info: &BootInformation, mbi_addr: u64) {
    if let Some(map) = info.memory_map_tag() {
        // `memory_areas()` asserts `entry_size == 24` (GRUB's §3.6.8
        // value): a bootloader that lied panics into our loud panic path
        // instead of mis-iterating — no UB, the tag walk was already
        // bounds-validated by the crate.
        for area in map.memory_areas() {
            if area.typ() == MemoryAreaType::Available {
                set_range(
                    area.start_address(),
                    area.start_address().saturating_add(area.size()),
                    false,
                );
            }
        }
    }
    // Re-reservations (order matters: free first, then reserve).
    set_range(0, 1 << 20, true); // conventional memory below 1 MiB
    let (ks, ke) = kernel_range();
    set_range(ks, ke, true); // kernel image, rounded out to whole frames
    let mbi_end = mbi_addr.saturating_add(info.total_size() as u64);
    set_range(mbi_addr, mbi_end, true);
}

/// Set frames in `[start, end)` to used/free.
///
/// `used=true` reserves every frame the range *touches* (conservative);
/// `used=false` frees only frames *fully inside* the range (a straddling
/// frame may hold non-RAM data, so it must stay reserved).
fn set_range(start: u64, end: u64, used: bool) {
    if end <= start {
        return;
    }
    let (first, last_exclusive) = if used {
        (start / FRAME_SIZE, end.div_ceil(FRAME_SIZE))
    } else {
        (start.div_ceil(FRAME_SIZE), end / FRAME_SIZE)
    };
    // Clamp to tracked space: regions may legitimately extend past 4 GiB.
    for n in first.min(TOTAL_FRAMES)..last_exclusive.min(TOTAL_FRAMES) {
        set_frame(n, used);
    }
}

fn set_frame(n: u64, used: bool) {
    // Beyond 4 GiB: untracked, stays used (never handed out).
    let Some(word) = BITMAP.get((n / 64) as usize) else {
        return;
    };
    let mask = 1u64 << (n % 64);
    if used {
        word.fetch_or(mask, Ordering::Relaxed);
    } else {
        word.fetch_and(!mask, Ordering::Relaxed);
    }
}

fn is_used(n: u64) -> bool {
    match BITMAP.get((n / 64) as usize) {
        Some(word) => word.load(Ordering::Relaxed) & (1u64 << (n % 64)) != 0,
        None => true, // untracked ⇒ conservatively used
    }
}

/// Hand out the lowest free frame. `None` when memory is exhausted.
pub fn alloc() -> Option<Frame> {
    for (wi, word) in BITMAP.iter().enumerate() {
        let mut current = word.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                break; // this word is full, next
            }
            let bit = (!current).trailing_zeros();
            let new = current | (1u64 << bit);
            // Relaxed: single boot core + interrupts; CAS guarantees the
            // bit is claimed exactly once either way.
            match word.compare_exchange_weak(current, new, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Some(Frame((wi as u64) * 64 + u64::from(bit))),
                Err(actual) => current = actual, // raced (or spurious), retry
            }
        }
    }
    None
}

/// Return a frame to the pool. Double-free is a caller bug: it only clears
/// an already-clear bit (no corruption, but the frame may be handed out
/// twice later).
pub fn free(frame: Frame) {
    set_frame(frame.0, false);
}

/// Number of frames currently free (cross-checked against [`alloc`] in
/// [`selftest`]). The shell's `meminfo` builtin reports it.
pub fn free_count() -> u64 {
    BITMAP
        .iter()
        .map(|w| u64::from((!w.load(Ordering::Relaxed)).count_ones()))
        .sum()
}

/// (start, end) of the kernel image, from symbols defined in `linker.ld`.
fn kernel_range() -> (u64, u64) {
    unsafe extern "C" {
        static kernel_start: u8;
        static kernel_end: u8;
    }
    // `addr_of!` only computes the address; linker symbols are never
    // dereferenced (they may not even have backing memory).
    let start = core::ptr::addr_of!(kernel_start) as u64;
    let end = core::ptr::addr_of!(kernel_end) as u64;
    (start, end)
}

/// Print a fatal memory error and park the CPU (no `format!` — no allocator
/// yet, and `serial_println!` formats straight to the UART).
fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: memory: {msg}");
    crate::halt()
}

fn check_range_used(start: u64, end: u64, what: &str) {
    let mut n = start / FRAME_SIZE;
    let last = end.div_ceil(FRAME_SIZE);
    while n < last {
        if !is_used(n) {
            serial_println!("FATAL: {what} frame {n} ({:#x}) is free", n * FRAME_SIZE);
            crate::halt();
        }
        n += 1;
    }
}

fn must_alloc() -> Frame {
    match alloc() {
        Some(f) => f,
        None => fatal("alloc failed while frames were reported free"),
    }
}

/// Machine-checked allocator test: prints `MEM_OK` on success, otherwise
/// dumps context and parks (so `cargo xtask smoke` fails on the marker).
pub fn selftest(info: &BootInformation, mbi_addr: u64) {
    let f0 = free_count();
    serial_println!(
        "memory: {f0} frames free ({} KiB)",
        f0 * (FRAME_SIZE / 1024)
    );
    if f0 == 0 {
        fatal("no free frames after init");
    }

    // Reservations must hold: low memory, kernel image, mbi.
    let (ks, ke) = kernel_range();
    serial_println!("memory: kernel {:#x}..{:#x}", ks, ke);
    check_range_used(0, 1 << 20, "low memory");
    check_range_used(ks, ke, "kernel image");
    let mbi_end = mbi_addr.saturating_add(info.total_size() as u64);
    check_range_used(mbi_addr, mbi_end, "mbi");

    // Exhaustion: every free bit must be handed out exactly once. A missed
    // bit leaves free_count() > 0; a duplicate/never-set bit either loops
    // past f0 or leaves bits behind — both caught below.
    let mut n = 0u64;
    while alloc().is_some() {
        n += 1;
        if n > f0 {
            fatal("allocator returned more frames than were free");
        }
    }
    if n != f0 {
        fatal("exhaustion count != free count (missed or duplicated frame)");
    }
    if free_count() != 0 {
        fatal("free bits remain after exhaustion");
    }

    // Deterministic re-init: same inputs must yield the same state.
    init(info, mbi_addr);
    let f1 = free_count();
    if f1 != f0 {
        fatal("re-init changed the free-frame count");
    }

    // alloc/free roundtrip: distinct frames, freed frame reused.
    let a = must_alloc();
    let b = must_alloc();
    if a == b {
        fatal("allocator returned the same frame twice");
    }
    free(a);
    let c = must_alloc();
    if c != a {
        fatal("freed frame was not the next one handed out");
    }
    free(b);
    free(c);
    if free_count() != f0 {
        fatal("free count drifted after alloc/free roundtrip");
    }

    serial_println!(
        "memory: sample frame {:#x}..{:#x}",
        a.start_phys(),
        a.start_phys() + FRAME_SIZE
    );
    serial_println!("MEM_OK"); // machine-checked by `cargo xtask smoke`
}
