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

    /// Build a frame handle from a physical address (page-table entry
    /// decode). Refuses unaligned or untracked (> 4 GiB) addresses.
    #[allow(dead_code)] // used by the userland page-table walker
    pub fn from_phys(addr: u64) -> Option<Self> {
        if !addr.is_multiple_of(FRAME_SIZE) || addr >= TRACKED_BYTES {
            return None;
        }
        Some(Self(addr / FRAME_SIZE))
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

/// Carve a **contiguous** run of frames for the kernel heap.
///
/// [`alloc`] hands out the *lowest free* frame, so addresses arrive in
/// increasing order, but they are not guaranteed contiguous: the kernel
/// image, the mbi and reserved E820 regions punch holes in the free
/// pool. We therefore allocate frames and verify contiguity as we go
/// (a run only extends when `next == run_start + run_len * FRAME_SIZE`;
/// any other address closes the run and starts a new one), remember
/// every run, and keep the **longest** one — the longest contiguous
/// prefix of the allocation sequence. Allocation stops early as soon as
/// one run reaches `target` frames; the search budget is twice that, so
/// a couple of holes cannot starve the carve.
///
/// Frames in the runs that lose are returned to the pool (they were all
/// allocated by this call, so no other owner exists), and the winning
/// run stays marked used — that is what makes the region safe for the
/// heap: exclusive, never handed out twice, identity-mapped RAM
/// (`entry.S` maps the first 4 GiB) that the E820 map lists as
/// available.
///
/// Returns `(start_phys, frames)` of the chosen run, or `None` if the
/// pool has no frames at all.
pub fn carve_contiguous(target: u64) -> Option<(u64, u64)> {
    /// Room for a handful of holes (kernel, mbi, ACPI/E820 reservations).
    const MAX_RUNS: usize = 128;
    // Search budget: twice the target, so holes cost us nothing.
    let budget = target.saturating_mul(2);

    let mut runs = [(0u64, 0u64); MAX_RUNS]; // (start, len) of every run seen
    let mut n_runs = 0usize;
    let mut cur = (0u64, 0u64); // run currently being extended
    let mut taken = 0u64;

    while taken < budget {
        let Some(f) = alloc() else { break };
        taken += 1;
        let phys = f.start_phys();
        if cur.1 != 0 && phys == cur.0 + cur.1 * FRAME_SIZE {
            cur.1 += 1; // contiguous: extend the run
        } else {
            // Not contiguous (or first frame): record the run being closed.
            if n_runs == MAX_RUNS {
                fatal("heap carve: free pool too fragmented");
            }
            runs[n_runs] = cur;
            n_runs += 1;
            cur = (phys, 1);
        }
        if cur.1 >= target {
            break; // long enough — stop allocating
        }
    }
    if n_runs == MAX_RUNS {
        fatal("heap carve: free pool too fragmented");
    }
    runs[n_runs] = cur;
    n_runs += 1;

    // The winning run: the longest recorded (first wins on a tie; a
    // run that reached `target` is necessarily the longest, since every
    // earlier run closed before reaching it).
    let mut best = (0u64, 0u64);
    for &run in &runs[..n_runs] {
        if run.1 > best.1 {
            best = run;
        }
    }
    if best.1 == 0 {
        return None; // pool was empty
    }

    // Give back every frame outside the winning run (all of them were
    // allocated by this call — the runs are disjoint by construction).
    for &(start, len) in &runs[..n_runs] {
        if (start, len) == best || len == 0 {
            continue;
        }
        let mut n = start / FRAME_SIZE;
        let end = (start + len * FRAME_SIZE) / FRAME_SIZE;
        while n < end {
            set_frame(n, false);
            n += 1;
        }
    }
    Some(best)
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

/// User address-space machinery. Scoped `allow(dead_code)` because the
/// integrator adds `mod userland;` (the only consumer) after this branch.
#[allow(dead_code)]
mod user_space {
    use super::*;

    // --- User address spaces (hito U1) -------------------------------------
    //
    // The boot map in `entry.S` identity-maps the first 4 GiB with 2 MiB pages
    // and PML4[0] as the only top-level entry. A process gets a *new* PML4 whose
    // entry 0 is a copy of that kernel entry with U/S cleared (so kernel RAM is
    // reachable from ring 0 but never from ring 3), and whose entry 1 owns a
    // private PDPT/PD/PT hierarchy for user pages. All table frames come from
    // the allocator below and are returned by `free_user_page_table` on exit.
    //
    // No heap is involved: the frame inventory lives in fixed arrays.

    /// First user virtual address (PML4[1], 512 GiB). Mirrors
    /// `userland::elf::USER_BASE` — keep both in sync.
    pub const USER_BASE: u64 = 0x0000_0080_0000_0000;
    /// End of the user region: one PDPT entry (1 GiB) above [`USER_BASE`].
    pub const USER_END: u64 = USER_BASE + (1 << 30);
    /// 16 KiB of zeroed, writable user stack at the top of that region.
    pub const USER_STACK_SIZE: u64 = 16 * 1024;
    /// Kernel stack for the ring 0 ↔ ring 3 transition (identity-mapped).
    pub const KERNEL_STACK_SIZE: u64 = FRAME_SIZE;

    /// Root + PDPT + PD + PT frames per process. 64 is far above the handful
    /// the first user binaries need; hitting the cap is a loud OOM, never a
    /// silent table overwrite.
    const MAX_USER_TABLES: usize = 64;
    /// Data pages tracked per process so they can be freed on exit.
    const MAX_USER_PAGES: usize = 128;

    const PT_PRESENT: u64 = 1 << 0;
    const PT_RW: u64 = 1 << 1;
    const PT_USER: u64 = 1 << 2;
    const PHYS_MASK: u64 = 0x000f_ffff_ffff_f000;

    /// Why a user mapping was refused.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum UserMapError {
        /// Address outside `[USER_BASE, USER_END)`.
        NotUserAddress,
        /// No table frames left (table inventory full or allocator exhausted).
        TableLimit,
        /// Data-page inventory full.
        PageLimit,
        /// A page-table entry already pointed somewhere: refuse to leak the
        /// frame the caller just allocated.
        AlreadyMapped,
        /// A table entry held a physical address this allocator cannot own.
        UntrackedFrame,
    }

    /// One process's page tables and the frames backing them.
    #[derive(Debug)]
    pub struct UserPageTable {
        /// Physical address of the new PML4; load it into CR3 on switch.
        pub root: Frame,
        tables: [Frame; MAX_USER_TABLES],
        n_tables: usize,
        pages: [Frame; MAX_USER_PAGES],
        n_pages: usize,
    }

    /// Hand out a zeroed frame. Used for page tables (so no stale entries can
    /// ever make a user page appear present) and for user data/stack pages (so
    /// a fresh process cannot read the previous owner's bytes).
    pub fn alloc_zeroed() -> Option<Frame> {
        let frame = alloc()?;
        // SAFETY: `alloc` returned this frame exclusively; it is inside the
        // tracked 4 GiB and the boot map identity-maps every such frame as
        // supervisor RW. Single-core boot, no other owner writes it.
        unsafe { core::ptr::write_bytes(frame.start_phys() as *mut u8, 0, FRAME_SIZE as usize) };
        Some(frame)
    }

    /// Read a 64-bit page-table entry through the identity map.
    fn read_entry(table: Frame, index: usize) -> u64 {
        let ptr = (table.start_phys() as usize + index * 8) as *const u64;
        // SAFETY: `table` is an owned, allocated, identity-mapped frame and
        // `index < 512` (all callers mask the virtual address with 0x1ff), so
        // this 8-byte read stays inside it. No concurrent writer here.
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write a 64-bit page-table entry through the identity map.
    fn write_entry(table: Frame, index: usize, value: u64) {
        let ptr = (table.start_phys() as usize + index * 8) as *mut u64;
        // SAFETY: same ownership/bounds contract as `read_entry`; the frame is
        // exclusively ours and the entry is 8-byte aligned inside it.
        unsafe { core::ptr::write_volatile(ptr, value) };
    }

    /// CR3's physical base — the live kernel PML4. Reading CR3 avoids depending
    /// on an assembler symbol (`pml4`) that another milestone owns.
    fn current_pml4() -> Option<Frame> {
        let cr3: u64;
        // SAFETY: `mov %cr3, reg` is a privileged read, and we are in ring 0
        // since `entry.S` switched to long mode. No side effects, no stack use.
        unsafe {
            core::arch::asm!("mov {value}, cr3", value = out(reg) cr3, options(nomem, nostack))
        };
        Frame::from_phys(cr3 & PHYS_MASK)
    }

    impl UserPageTable {
        fn new(root: Frame) -> Self {
            let table = Self {
                root,
                tables: [root; MAX_USER_TABLES],
                n_tables: 1,
                pages: [root; MAX_USER_PAGES],
                n_pages: 0,
            };
            // Only `tables[..n_tables]` / `pages[..n_pages]` are live; the
            // placeholders above are never freed (they alias `root`, which is
            // freed exactly once through `tables[0]`).
            table
        }

        fn push_table(&mut self, frame: Frame) -> Result<(), UserMapError> {
            let slot = self
                .tables
                .get_mut(self.n_tables)
                .ok_or(UserMapError::TableLimit)?;
            *slot = frame;
            self.n_tables += 1;
            Ok(())
        }

        fn record_page(&mut self, frame: Frame) -> Result<(), UserMapError> {
            let slot = self
                .pages
                .get_mut(self.n_pages)
                .ok_or(UserMapError::PageLimit)?;
            *slot = frame;
            self.n_pages += 1;
            Ok(())
        }
    }

    /// Create a new process PML4: copy the kernel identity map from CR3 into
    /// entry 0 with U/S cleared, then let [`map_user_page`] build the private
    /// PML4[1] hierarchy on demand.
    pub fn create_user_page_table() -> Option<UserPageTable> {
        let root = alloc_zeroed()?;
        let kernel_pml4 = current_pml4()?;
        let kernel_entry = read_entry(kernel_pml4, 0);
        if kernel_entry & PT_PRESENT == 0 {
            free(root);
            return None;
        }
        // Lower levels of the boot map are already supervisor-only (2 MiB PDE
        // value 0x83); clearing U/S here makes the entire identity map
        // inaccessible from ring 3 at the top level as well.
        write_entry(root, 0, kernel_entry & !PT_USER);
        Some(UserPageTable::new(root))
    }

    /// Walk `parent` and return (creating if absent) the child table for one
    /// virtual-address level. New tables are user-accessible at every level.
    fn child_table(
        space: &mut UserPageTable,
        parent: Frame,
        index: usize,
    ) -> Result<Frame, UserMapError> {
        let entry = read_entry(parent, index);
        if entry & PT_PRESENT != 0 {
            return Frame::from_phys(entry & PHYS_MASK).ok_or(UserMapError::UntrackedFrame);
        }
        let frame = alloc_zeroed().ok_or(UserMapError::TableLimit)?;
        space.push_table(frame)?;
        write_entry(
            parent,
            index,
            frame.start_phys() | PT_PRESENT | PT_RW | PT_USER,
        );
        Ok(frame)
    }

    /// Map one 4 KiB `frame` at `virt` as a user page. `writable` controls R/W;
    /// U/S is set at PML4, PDPT, PD and PT (x86-64 requires it at *every*
    /// level). Kernel identity mappings are in PML4[0] and stay supervisor-only.
    pub fn map_user_page(
        space: &mut UserPageTable,
        virt: u64,
        frame: Frame,
        writable: bool,
    ) -> Result<(), UserMapError> {
        if !(USER_BASE..USER_END).contains(&virt) || !virt.is_multiple_of(FRAME_SIZE) {
            return Err(UserMapError::NotUserAddress);
        }
        let pdpt = child_table(space, space.root, ((virt >> 39) & 0x1ff) as usize)?;
        let pd = child_table(space, pdpt, ((virt >> 30) & 0x1ff) as usize)?;
        let pt = child_table(space, pd, ((virt >> 21) & 0x1ff) as usize)?;
        let leaf = (virt >> 12) & 0x1ff;
        if read_entry(pt, leaf as usize) & PT_PRESENT != 0 {
            return Err(UserMapError::AlreadyMapped);
        }
        write_entry(
            pt,
            leaf as usize,
            frame.start_phys() | PT_PRESENT | PT_USER | (if writable { PT_RW } else { 0 }),
        );
        space.record_page(frame)
    }

    /// Walk the hierarchy for `virt` without switching CR3. Returns the backing
    /// frame and the leaf flags; `None` when any level is absent or non-user.
    /// The boot proof uses this to assert that every segment/stack page really
    /// is present and U/S=1 before printing `ELF_OK`.
    pub fn user_page_frame(space: &UserPageTable, virt: u64) -> Option<(Frame, u64)> {
        if !(USER_BASE..USER_END).contains(&virt) || !virt.is_multiple_of(FRAME_SIZE) {
            return None;
        }
        let mut table = space.root;
        for shift in [39, 30, 21] {
            let index = ((virt >> shift) & 0x1ff) as usize;
            let entry = read_entry(table, index);
            if entry & (PT_PRESENT | PT_USER) != (PT_PRESENT | PT_USER) {
                return None;
            }
            table = Frame::from_phys(entry & PHYS_MASK)?;
        }
        let entry = read_entry(table, ((virt >> 12) & 0x1ff) as usize);
        if entry & (PT_PRESENT | PT_USER) != (PT_PRESENT | PT_USER) {
            return None;
        }
        Some((Frame::from_phys(entry & PHYS_MASK)?, entry & 0xfff))
    }

    /// Return every frame this table owns (including its root). Never call on
    /// a table still loaded in CR3: switch back to the kernel PML4 first.
    pub fn free_user_page_table(space: &UserPageTable) {
        for &frame in space.tables.iter().take(space.n_tables) {
            free(frame);
        }
        for &frame in space.pages.iter().take(space.n_pages) {
            free(frame);
        }
    }
}

// Consumers arrive with the integrator's `mod userland;`; keep the public
// names at `memory::*` so both the loader and m-privilege use one API.
#[allow(unused_imports)]
pub use user_space::*;
