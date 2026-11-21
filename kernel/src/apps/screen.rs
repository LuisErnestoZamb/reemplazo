//! The apps-side screen layer: an **off-screen cell buffer** sized
//! from the live VGA geometry ([`crate::vga::dims`]), staged by the
//! widgets and [`flush_diff`]'d into the text buffer.
//!
//! The cell model is the VGA text entry itself — `(char, fg, bg)` →
//! glyph byte + attribute byte (`attr = fg | bg << 4`, 4-bit indices),
//! the exact 2-byte format [`crate::vga`] writes. Nothing here emits
//! ANSI: the log path's ANSI-swallowing state machine and the
//! `serial_print!` mirror keep their own, untouched behaviour (the
//! boot log is a *sibling* of this path, not a substrate).
//!
//! # Diffing against the real screen, not a shadow
//!
//! [`flush_diff`] compares the staged buffer with what is **actually**
//! in `0xb8000` (via [`crate::vga::peek_cell`]) and writes only the
//! differing cells. Comparing against the hardware instead of a cached
//! copy means any stray writer (the shell's mirrored output between
//! two app sessions) self-heals on the next flush rather than silently
//! desyncing — and after every flush, screen == buffer by construction,
//! which is what the `TUI_OK` readback relies on.
//!
//! # Glyphs: ASCII + a CP437 subset (documented limit)
//!
//! The BIOS font is **CP437**. ASCII passes through, and the few
//! non-ASCII glyphs A1's frame draws (ratatui's plain box-drawing
//! borders, the status bar's arrows and middle dot) are mapped to
//! their documented CP437 codes; everything else — including wide
//! (CJK) characters, which are also drawn as a single cell — falls
//! back to `?`. A full Unicode→CP437 table is later polish.
//!
//! # SAFETY / capacity
//!
//! The buffer lives in a `static mut` (the `READ_STORAGE` idiom from
//! `tls.rs`): fixed size, no stack temporaries, no per-frame heap.
//! The contract is **single consumer** — one app session at a time on
//! the boot/mainline stack, and no IRQ handler touches the screen
//! layer (IRQ handlers never print, see `serial.rs`), so preemption
//! cannot alias the `&mut` this module hands out.

use core::fmt;

/// Widest text geometry the cell buffer accepts (GRUB's text modes
/// are 80-column class; 132-column modes fail soft as [`TooLarge`]).
pub const MAX_COLS: usize = 100;
/// Tallest text geometry the cell buffer accepts (80×25/30/50/60).
pub const MAX_ROWS: usize = 60;
/// Total staged cells (`MAX_COLS * MAX_ROWS` × 2 bytes ≈ 12 KiB .bss).
const MAX_CELLS: usize = MAX_COLS * MAX_ROWS;

/// Default attribute: light grey on black — the same byte `vga.rs`
/// writes for mirrored log output, so a blank staged cell and a blank
/// text cell are indistinguishable.
const ATTR: u8 = 0x07;

/// One staged text cell: the exact two bytes the VGA text buffer
/// holds (glyph + attribute).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Cell {
    pub glyph: u8,
    pub attr: u8,
}

impl Cell {
    /// A blank cell — space, default attribute.
    pub const BLANK: Self = Self {
        glyph: b' ',
        attr: ATTR,
    };
}

/// Why the screen layer is unavailable. Implements [`core::error::Error`]
/// because it is also the ratatui [`Backend`](ratatui::backend::Backend)'s
/// error type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScreenError {
    /// The VGA mirror is off — no text framebuffer to draw into.
    NoConsole,
    /// The text geometry exceeds this layer's fixed cell buffer.
    TooLarge,
    /// A `ClearType` other than `ClearType::All` — full-screen apps
    /// only ever clear everything.
    UnsupportedClear,
}

impl fmt::Display for ScreenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoConsole => f.write_str("no text console (VGA mirror disabled)"),
            Self::TooLarge => {
                write!(
                    f,
                    "text geometry exceeds the cell buffer ({MAX_COLS}x{MAX_ROWS})"
                )
            }
            Self::UnsupportedClear => {
                f.write_str("only ClearType::All is supported (full-screen apps)")
            }
        }
    }
}

impl core::error::Error for ScreenError {}

/// The off-screen buffer plus the geometry it was sized for.
/// `cols == 0 || rows == 0` means "not open" (the `static` start
/// state), which every entry point treats as a no-op/failure rather
/// than indexing anything.
struct Screen {
    cols: usize,
    rows: usize,
    cells: [Cell; MAX_CELLS],
}

// SAFETY — the `READ_STORAGE` idiom: written and read only from the
// boot/mainline stack by one app session at a time (single consumer,
// documented above); no IRQ handler and no second core touches it.
static mut SCREEN: Screen = Screen {
    cols: 0,
    rows: 0,
    cells: [Cell::BLANK; MAX_CELLS],
};

/// Exclusive access to the staged buffer — the single-consumer
/// boundary (see the module SAFETY note).
fn screen_mut() -> &'static mut Screen {
    // SAFETY: raw-pointer deref of a `static mut` whose access
    // contract is the module's single-consumer rule; callers never
    // hold two of these at once (each public fn takes it once).
    unsafe { &mut *core::ptr::addr_of_mut!(SCREEN) }
}

/// Shared access to the staged buffer (read paths that must not
/// alias a live `&mut` — they are called from separate functions).
fn screen_ref() -> &'static Screen {
    // SAFETY: as `screen_mut`, read-only side of the same contract.
    unsafe { &*core::ptr::addr_of!(SCREEN) }
}

/// Open (or re-open) the screen layer for the current VGA geometry
/// and **blank the staged buffer**: a session starts from a clean
/// slate, so the first flush can never inherit stale cells from a
/// previous app (the shell may have printed over the text buffer in
/// between — see [`flush_diff`]'s read-what's-really-there diff).
///
/// Fails soft with [`ScreenError`] — zero/absent geometry is
/// `NoConsole`, oversized geometry is `TooLarge`; nothing panics.
pub fn open() -> Result<(), ScreenError> {
    let (cols, rows) = crate::vga::dims().ok_or(ScreenError::NoConsole)?;
    if cols == 0 || rows == 0 {
        return Err(ScreenError::NoConsole);
    }
    if cols > MAX_COLS || rows > MAX_ROWS {
        return Err(ScreenError::TooLarge);
    }
    // Both dimensions are ≤ their MAX_* (checked above), so the
    // product fits `usize` and is ≤ `MAX_CELLS` — no overflow path.
    let Some(cells) = cols.checked_mul(rows) else {
        return Err(ScreenError::TooLarge);
    };
    let screen = screen_mut();
    screen.cols = cols;
    screen.rows = rows;
    // `get_mut(..cells)` instead of slicing: even a future cap change
    // degrades to "blank less", never to a panic.
    if let Some(slot) = screen.cells.get_mut(..cells) {
        slot.fill(Cell::BLANK);
    }
    Ok(())
}

/// The open geometry `(cols, rows)`, or `None` when the layer is not
/// open. This is the only source of truth for app layout — nothing
/// here hardcodes 80×25.
pub fn dims() -> Option<(usize, usize)> {
    let screen = screen_ref();
    if screen.cols == 0 || screen.rows == 0 {
        None
    } else {
        Some((screen.cols, screen.rows))
    }
}

/// Stage one cell: the `(char, fg, bg)` cell model encoded to the
/// VGA text entry (glyph via the CP437 mapping, `attr = fg | bg<<4`;
/// `fg`/`bg` are already4-bit indices). Out-of-range coordinates are
/// dropped — returns `false`, never panics.
pub fn put(x: u16, y: u16, ch: char, fg: u8, bg: u8) -> bool {
    let (x, y) = (usize::from(x), usize::from(y));
    let screen = screen_mut();
    if screen.cols == 0 || screen.rows == 0 || x >= screen.cols || y >= screen.rows {
        return false;
    }
    // `y < rows && x < cols` and `rows*cols ≤ MAX_CELLS` (open's
    // invariant) keep this index in range; `get_mut` proves it anyway.
    let Some(index) = y
        .checked_mul(screen.cols)
        .and_then(|row| row.checked_add(x))
    else {
        return false;
    };
    let Some(cell) = screen.cells.get_mut(index) else {
        return false;
    };
    *cell = Cell {
        glyph: glyph(ch),
        attr: (fg & 0x0F) | ((bg & 0x0F) << 4),
    };
    true
}

/// Blank the staged buffer (no hardware write until [`flush_diff`]).
pub fn clear() {
    let screen = screen_mut();
    let Some(cells) = screen.cols.checked_mul(screen.rows) else {
        return;
    };
    if let Some(slot) = screen.cells.get_mut(..cells) {
        slot.fill(Cell::BLANK);
    }
}

/// Push the staged buffer into the text buffer, writing only cells
/// that differ from what is really on screen. No-op while the mirror
/// is disabled ([`crate::vga`] never writes then) and while the layer
/// is not open.
pub fn flush_diff() {
    let screen = screen_ref();
    if screen.cols == 0 || screen.rows == 0 {
        return;
    }
    for y in 0..screen.rows {
        for x in 0..screen.cols {
            // y < rows && x < cols ⇒ the product fits, but every step
            // stays checked so no input can index out of range.
            let Some(index) = y
                .checked_mul(screen.cols)
                .and_then(|row| row.checked_add(x))
            else {
                return; // unreachable while open's invariants hold
            };
            let Some(desired) = screen.cells.get(index) else {
                return;
            };
            if let Some(current) = crate::vga::peek_cell(x, y)
                && current != (desired.glyph, desired.attr)
            {
                let _ = crate::vga::put_cell(x, y, desired.glyph, desired.attr);
            }
        }
    }
}

/// Map a `char` to the glyph byte the BIOS font renders (CP437):
/// printable ASCII passes through, A1's box-drawing/arrow/dot glyphs
/// use their documented CP437 codes, everything else is `?`.
fn glyph(ch: char) -> u8 {
    match ch {
        c if c.is_ascii() && !c.is_control() => c as u8,
        // The subset A1's frame needs — a full CP437 table is later
        // polish (module docs).
        '\u{2500}' => 0xC4, // ─  BOX DRAWINGS LIGHT HORIZONTAL
        '\u{2502}' => 0xB3, // │  BOX DRAWINGS LIGHT VERTICAL
        '\u{250C}' => 0xDA, // ┌  BOX DRAWINGS LIGHT DOWN AND RIGHT
        '\u{2510}' => 0xBF, // ┐  BOX DRAWINGS LIGHT DOWN AND LEFT
        '\u{2514}' => 0xC0, // └  BOX DRAWINGS LIGHT UP AND RIGHT
        '\u{2518}' => 0xD9, // ┘  BOX DRAWINGS LIGHT UP AND LEFT
        '\u{2191}' => 0x18, // ↑  UP ARROW
        '\u{2193}' => 0x19, // ↓  DOWN ARROW
        '\u{00B7}' => 0xFA, // ·  MIDDLE DOT
        _ => b'?',
    }
}
