//! Kernel-owned VGA text service for ring-3 processes (hito 3).
//!
//! This is the migrated core of `apps::screen::flush_diff`: an **off-screen
//! cell buffer** staged by the user process through `VgaPutCell`/`VgaClear`,
//! flushed into `0xb8000` only after a diff against what is *really* in the
//! text buffer. The diff reads hardware ([`crate::vga::peek_cell`]) instead
//! of a cached shadow, so a stray kernel writer (the shell's mirrored log
//! between sessions) self-heals on the next flush.
//!
//! The user process never sees a physical address and never supplies an
//! unbounded range: every `(x, y)` is bounds-checked against the live VGA
//! geometry and the fixed staging buffer. Ownership of the service is
//! checked one layer up, in [`super::console`] (the PCB's `owns_console`
//! flag), so a second process calling these functions directly from kernel
//! code is not a supported path.
//!
//! # SAFETY / capacity
//!
//! The staging buffer is a `static mut` with a fixed cap (≈12 KiB of .bss).
//! It has the same single-consumer contract as the old apps screen layer:
//! one console owner at a time, no IRQ handler touches it, single core.

use crate::vga;

/// Widest staged geometry accepted (GRUB leaves an 80-column text mode).
pub const MAX_COLS: usize = 100;
/// Tallest staged geometry accepted (80×25/30/50/60).
pub const MAX_ROWS: usize = 60;
const MAX_CELLS: usize = MAX_COLS * MAX_ROWS;

/// Default attribute: light grey on black — what `vga.rs` mirrors use.
const ATTR: u8 = 0x07;

/// One staged text cell: the exact two bytes the VGA text buffer holds.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Cell {
    glyph: u8,
    attr: u8,
}

impl Cell {
    const BLANK: Self = Self {
        glyph: b' ',
        attr: ATTR,
    };
}

struct Screen {
    cols: usize,
    rows: usize,
    cells: [Cell; MAX_CELLS],
}

// SAFETY — single console owner, single core, IF=0 across the syscall
// dispatch that reaches this module; no IRQ handler writes the screen
// layer (the old `apps::screen` contract, kept verbatim).
static mut SCREEN: Screen = Screen {
    cols: 0,
    rows: 0,
    cells: [Cell::BLANK; MAX_CELLS],
};

fn screen_mut() -> &'static mut Screen {
    // SAFETY: the single-consumer contract above; each public function
    // takes this at most once and never holds it across another call.
    unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) }
}

fn screen_ref() -> &'static Screen {
    // SAFETY: read-only side of the same contract.
    unsafe { &*core::ptr::addr_of!(SCREEN) }
}

/// Bind the staging buffer to the live text geometry and blank it.
/// Fails soft: no console, or a geometry above our caps, leaves the buffer
/// closed. Called automatically by [`ensure_open`].
fn open() -> bool {
    let Some((cols, rows)) = vga::dims() else {
        return false;
    };
    if cols == 0 || rows == 0 || cols > MAX_COLS || rows > MAX_ROWS {
        return false;
    }
    let Some(cells) = cols.checked_mul(rows) else {
        return false;
    };
    let screen = screen_mut();
    screen.cols = cols;
    screen.rows = rows;
    // `get_mut` instead of slicing: a future cap change degrades to
    // "blank less", never to a panic.
    if let Some(slot) = screen.cells.get_mut(..cells) {
        slot.fill(Cell::BLANK);
    }
    true
}

fn ensure_open() -> bool {
    let already_open = {
        let screen = screen_ref();
        screen.cols != 0 && screen.rows != 0
    };
    already_open || open()
}

/// Live geometry `(cols, rows)` of the text console, or `None` when the
/// VGA mirror is disabled. This is what `VgaDims` returns to user space.
pub fn dims() -> Option<(usize, usize)> {
    vga::dims()
}

/// Stage one raw text cell. `(x, y, glyph, attr)` are already kernel-side
/// integers (the syscall layer converts from the SysV argument registers).
/// Out-of-range coordinates are dropped — `false`, never a panic.
pub fn put(x: usize, y: usize, glyph: u8, attr: u8) -> bool {
    if !ensure_open() {
        return false;
    }
    let screen = screen_mut();
    if x >= screen.cols || y >= screen.rows {
        return false;
    }
    let Some(index) = y.checked_mul(screen.cols).and_then(|r| r.checked_add(x)) else {
        return false;
    };
    let Some(cell) = screen.cells.get_mut(index) else {
        return false;
    };
    *cell = Cell { glyph, attr };
    true
}

/// Blank the staged buffer. No hardware write until [`flush`].
pub fn clear() {
    if !ensure_open() {
        return;
    }
    let screen = screen_mut();
    let Some(cells) = screen.cols.checked_mul(screen.rows) else {
        return;
    };
    if let Some(slot) = screen.cells.get_mut(..cells) {
        slot.fill(Cell::BLANK);
    }
}

/// Push the staged cells into `0xb8000`, writing only those whose
/// `(glyph, attr)` differ from what the hardware actually holds. This is
/// `apps::screen::flush_diff`, moved into ring 0 as a service.
pub fn flush() {
    if !ensure_open() {
        return;
    }
    let screen = screen_ref();
    for y in 0..screen.rows {
        for x in 0..screen.cols {
            // Every step is checked even though the open invariant keeps
            // the index in range — no input can index out of bounds.
            let Some(index) = y.checked_mul(screen.cols).and_then(|r| r.checked_add(x)) else {
                return;
            };
            let Some(desired) = screen.cells.get(index) else {
                return;
            };
            if let Some(current) = vga::peek_cell(x, y)
                && current != (desired.glyph, desired.attr)
            {
                let _ = vga::put_cell(x, y, desired.glyph, desired.attr);
            }
        }
    }
}

/// Read one raw cell **back from the hardware** (`VgaPeek`). `None` when
/// the mirror is off or the coordinates are out of range.
pub fn peek(x: usize, y: usize) -> Option<(u8, u8)> {
    vga::peek_cell(x, y)
}

/// Kernel-side self-proof of the service (no syscalls, no user buffer):
/// open, stage a distinctive cell, flush, read it back from `0xb8000`.
/// Returns `false` on any mismatch; callers decide what marker to emit.
pub fn prove() -> bool {
    const GLYPH: u8 = b'V';
    const ATTR_TEST: u8 = 0x1f;
    if !ensure_open() {
        return false;
    }
    let Some((_cols, _rows)) = dims() else {
        return false;
    };
    if !put(0, 0, GLYPH, ATTR_TEST) {
        return false;
    }
    flush();
    peek(0, 0) == Some((GLYPH, ATTR_TEST))
}
