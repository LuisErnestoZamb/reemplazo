//! The first full-screen app (milestone A1) and the ratatui plumbing
//! every app will share:
//!
//! - [`VgaBackend`] — a ratatui [`Backend`](ratatui::backend::Backend)
//!   over [`crate::apps::screen`]: `draw` stages cells, `flush` diffs
//!   them into the text buffer. The TUI never emits ANSI.
//! - [`render`] — the demo frame: a bordered `Block` titled
//!   `reemplazo tui`, a five-item selectable `List` with the highlight
//!   on the first entry, and a status bar (`↑/↓ move · Esc quit`).
//! - [`boot_proof`] — the automatic `TUI_OK` proof (render → read back
//!   from `0xb8000` → assert a deterministic sample), run between
//!   `INT_OK` and `SHELL_OK`.
//! - [`run`] — the `tui` shell builtin's interactive loop: arrows move
//!   the highlight, `Esc` returns to the prompt. Fails soft like every
//!   other builtin (shell.rs's contract).
//!
//! # Rendering path — the A1 build probe
//!
//! `ratatui = { version = "0.30", default-features = false }` cross
//! checks clean for `x86_64-unknown-none`: `ratatui`, `ratatui-core`
//! and `ratatui-widgets` are all `#![no_std]` + `alloc`, and with
//! default features off no `crossterm`/`std`/`serde`/`underline-color`
//! code is even compiled (the one `std::eprintln!` in
//! `ratatui-core`'s `Terminal::drop` is `#[cfg(feature = "std")]`).
//! So the documented hand-rolled widget fallback was **not** needed;
//! the probe result and the dependency review are recorded in this
//! milestone's commit.
//!
//! # Heap / stack accounting
//!
//! `Terminal` owns ratatui's two internal `Buffer`s (`Vec<Cell>`:
//! 2 × cols × rows ratatui cells ≈ 160 KiB at 80×25, allocated once
//! per session and freed when the `Terminal` drops) plus a handful of
//! transient widget `Vec`s per redraw — bounded, no growth across
//! frames. Our own staged buffer is the fixed `static mut` in
//! [`crate::apps::screen`] (zero heap), and nothing here puts a large
//! array on the boot stack.

use crate::apps::screen::{self, ScreenError};
use crate::keyboard::Key;
use ratatui::backend::{Backend, ClearType, WindowSize};
use ratatui::layout::{Position, Rect, Size};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, List, ListState, Paragraph};
use ratatui::{Frame, Terminal};

/// Block title — the boot proof reads it back from row 0.
const TITLE: &str = "reemplazo tui";
/// Status bar. `↑`/`↓`/`·` go through `screen::glyph`'s CP437 subset.
const STATUS: &str = "↑/↓ move · Esc quit";
/// The demo menu: ≥5 selectable items, the first one highlighted.
const MENU: [&str; 5] = [
    "new chat",
    "open editor",
    "load model config",
    "network status",
    "about reemplazo",
];
/// Highlight style (black on yellow) as the VGA attribute byte the
/// boot proof asserts: fg 0 | bg 3 << 4.
const HIGHLIGHT_ATTR: u8 = 0x30;
/// Status bar style (white on blue) as an attribute byte: fg 15 |
/// bg 4 << 4.
const STATUS_ATTR: u8 = 0x4F;
/// Smallest geometry the frame needs: 14 columns for the title, 19
/// for the status line, and three rows for the bordered list above
/// the status bar.
const MIN_COLS: usize = 20;
const MIN_ROWS: usize = 4;

// ---------------------------------------------------------------------------
// The demo view
// ---------------------------------------------------------------------------

/// Render one demo frame: bordered list on top, status bar below.
/// Geometry comes from `Frame::area()` (the backend's size, i.e. the
/// live text geometry) — never a hardcoded 80×25.
fn render(frame: &mut Frame, state: &mut ListState) {
    let area = frame.area();
    // One row for the status bar, the rest for the list. A degenerate
    // viewport (height 0) draws nothing instead of panicking.
    let Some(status_rows) = area.height.checked_sub(1) else {
        return;
    };
    let block_area = Rect::new(area.x, area.y, area.width, status_rows);
    let block = Block::bordered()
        .title(TITLE)
        .border_style(Style::new().fg(Color::Cyan));
    let list = List::new(MENU)
        .block(block)
        .highlight_symbol("> ")
        .highlight_style(Style::new().fg(Color::Black).bg(Color::Yellow));
    frame.render_stateful_widget(list, block_area, state);

    let status_area = Rect::new(area.x, area.y.saturating_add(status_rows), area.width, 1);
    let status = Paragraph::new(STATUS).style(Style::new().fg(Color::White).bg(Color::Blue));
    frame.render_widget(status, status_area);
}

/// Move the list selection one step, clamped to the menu — no
/// wrap-around, no `select_next` (which does not know our item count
/// until after the first render).
fn move_selection(state: &mut ListState, down: bool) {
    let last = MENU.len().saturating_sub(1);
    let current = state.selected().unwrap_or(0).min(last);
    let next = if down {
        current.saturating_add(1).min(last)
    } else {
        current.saturating_sub(1)
    };
    state.select(Some(next));
}

// ---------------------------------------------------------------------------
// The Backend
// ---------------------------------------------------------------------------

/// ratatui [`Backend`] over the VGA text buffer. `draw` stages the
/// cells ratatui's own double-buffer diff hands us; `flush` pushes the
/// staged buffer into `0xb8000` through [`screen::flush_diff`] (which
/// writes only what actually differs from what is on screen).
#[derive(Default)]
pub struct VgaBackend {
    /// Last position ratatui asked for (text mode has no programmable
    /// cursor *position* under us yet — `vga.rs` owns the console
    /// cursor; read back by [`Backend::get_cursor_position`]).
    cursor: Position,
}

impl Backend for VgaBackend {
    type Error = ScreenError;

    fn draw<'a, I>(&mut self, content: I) -> Result<(), Self::Error>
    where
        I: Iterator<Item = (u16, u16, &'a ratatui::buffer::Cell)>,
    {
        for (x, y, cell) in content {
            // First glyph of the symbol only: combining marks and the
            // second half of a wide (CJK) pair have no second VGA
            // cell — documented limit in `screen.rs`.
            let ch = cell.symbol().chars().next().unwrap_or(' ');
            let (fg, bg) = colors(cell);
            screen::put(x, y, ch, fg, bg);
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> Result<(), Self::Error> {
        // Not programmed yet: the hardware text cursor is outside
        // A1's scope (`vga.rs` never touches the CRT controller).
        // Tracked in ratatui's own state; harmless here.
        Ok(())
    }

    fn show_cursor(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn get_cursor_position(&mut self) -> Result<Position, Self::Error> {
        Ok(self.cursor)
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> Result<(), Self::Error> {
        self.cursor = position.into();
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Self::Error> {
        screen::clear();
        screen::flush_diff();
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> Result<(), Self::Error> {
        match clear_type {
            ClearType::All => self.clear(),
            // Line/region clears only exist for inline viewports;
            // full-screen apps never ask for them.
            _ => Err(ScreenError::UnsupportedClear),
        }
    }

    fn size(&self) -> Result<Size, Self::Error> {
        let (cols, rows) = screen::dims().ok_or(ScreenError::NoConsole)?;
        Ok(Size {
            width: u16::try_from(cols).map_err(|_| ScreenError::TooLarge)?,
            height: u16::try_from(rows).map_err(|_| ScreenError::TooLarge)?,
        })
    }

    fn window_size(&mut self) -> Result<WindowSize, Self::Error> {
        Ok(WindowSize {
            columns_rows: self.size()?,
            pixels: Size {
                width: 0,
                height: 0, // text mode: no pixel geometry
            },
        })
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        screen::flush_diff();
        Ok(())
    }
}

/// ratatui style → the two 4-bit VGA indices, applying the two
/// modifiers text mode can express: `BOLD` → the VGA bright bit on the
/// foreground, `REVERSED` → swapped colors. Underline/blink/dim/etc.
/// are dropped (documented limit — no per-cell underline in text
/// mode).
fn colors(cell: &ratatui::buffer::Cell) -> (u8, u8) {
    let mut fg = index(cell.fg, 0x07); // Reset = console default (vga.rs ATTR)
    let mut bg = index(cell.bg, 0x00);
    if cell.modifier.contains(Modifier::BOLD) && fg < 8 {
        fg |= 0x08;
    }
    if cell.modifier.contains(Modifier::REVERSED) {
        core::mem::swap(&mut fg, &mut bg);
    }
    (fg, bg)
}

/// ratatui [`Color`] → 4-bit VGA index; `Reset` resolves to the
/// caller's console default (foreground vs background differ).
fn index(color: Color, reset: u8) -> u8 {
    match color {
        Color::Reset => reset,
        Color::Black => 0x0,
        Color::Red => 0x1,
        Color::Green => 0x2,
        Color::Yellow => 0x3,
        Color::Blue => 0x4,
        Color::Magenta => 0x5,
        Color::Cyan => 0x6,
        Color::Gray => 0x7,
        Color::DarkGray => 0x8,
        Color::LightRed => 0x9,
        Color::LightGreen => 0xA,
        Color::LightYellow => 0xB,
        Color::LightBlue => 0xC,
        Color::LightMagenta => 0xD,
        Color::LightCyan => 0xE,
        Color::White => 0xF,
        Color::Indexed(n) => n & 0x0F,
        Color::Rgb(r, g, b) => nearest(r, g, b),
    }
}

/// The canonical 16-color EGA/VGA palette (the standard RGB values
/// behind indices 0..16) — nearest match for an arbitrary `Color::Rgb`.
const PALETTE: [(u8, u8, u8); 16] = [
    (0x00, 0x00, 0x00),
    (0xAA, 0x00, 0x00),
    (0x00, 0xAA, 0x00),
    (0xAA, 0x55, 0x00),
    (0x00, 0x00, 0xAA),
    (0xAA, 0x00, 0xAA),
    (0x00, 0xAA, 0xAA),
    (0xAA, 0xAA, 0xAA),
    (0x55, 0x55, 0x55),
    (0xFF, 0x55, 0x55),
    (0x55, 0xFF, 0x55),
    (0xFF, 0xFF, 0x55),
    (0x55, 0x55, 0xFF),
    (0xFF, 0x55, 0xFF),
    (0x55, 0xFF, 0xFF),
    (0xFF, 0xFF, 0xFF),
];

fn nearest(r: u8, g: u8, b: u8) -> u8 {
    let mut best = 0u8;
    let mut best_dist = u32::MAX;
    for (i, &(pr, pg, pb)) in PALETTE.iter().enumerate() {
        let dr = i32::from(r) - i32::from(pr);
        let dg = i32::from(g) - i32::from(pg);
        let db = i32::from(b) - i32::from(pb);
        // Squares of |Δ| ≤ 255 fit i32 with room to spare.
        let dist = (dr * dr + dg * dg + db * db) as u32;
        if dist < best_dist {
            best_dist = dist;
            best = i as u8;
        }
    }
    best
}

// ---------------------------------------------------------------------------
// The boot proof: TUI_OK
// ---------------------------------------------------------------------------

/// Render the demo frame, flush it into the text buffer, read it back
/// from `0xb8000` and assert a deterministic sample — the smoke
/// test's `TUI_OK` (printed between `INT_OK` and `SHELL_OK`). On any
/// mismatch: `FATAL:` + [`crate::halt`], like every other boot proof;
/// a genuinely absent text console just skips the proof (the same way
/// `VGA_OK` skips a non-text framebuffer). Afterwards the screen is
/// cleared and the console cursor reset, so the shell starts clean —
/// serial output is never reordered or suppressed.
pub fn boot_proof() {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: tui: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove_frame() {
        serial_println!("FATAL: tui: {why}");
        crate::halt();
    }
    serial_println!("TUI_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// Render once and verify what the text buffer really holds.
/// Fail-closed: every error string becomes a `FATAL:` line.
fn prove_frame() -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the demo frame (min 20x4)");
    }
    let mut state = ListState::default().with_selected(Some(0));
    let mut terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
    terminal
        .draw(|frame| render(frame, &mut state))
        .map_err(|_| "first frame failed")?;

    // Readback from the actual text buffer — after `flush_diff` the
    // buffer and the screen agree cell by cell, so the frame must be
    // there (VGA_OK checks its banner the same way).
    if !row_holds(0, TITLE.as_bytes()) {
        return Err("title missing from row 0");
    }
    let Some(first) = MENU.first() else {
        return Err("menu empty");
    };
    if !row_holds(1, first.as_bytes()) {
        return Err("first list item missing from row 1");
    }
    if !row_holds_attr(1, HIGHLIGHT_ATTR) {
        return Err("highlight attribute missing from row 1");
    }
    let Some(status_row) = rows.checked_sub(1) else {
        return Err("no status row");
    };
    // "Esc quit" — the ASCII tail of STATUS (the arrows are CP437).
    if !row_holds(status_row, b"Esc quit") {
        return Err("status bar missing from the last row");
    }
    if !row_holds_attr(status_row, STATUS_ATTR) {
        return Err("status attribute missing from the last row");
    }
    Ok(())
}

/// Does row `y` of the *actual* text buffer hold `needle` as
/// consecutive glyph bytes?
fn row_holds(y: usize, needle: &[u8]) -> bool {
    let Some((cols, rows)) = screen::dims() else {
        return false;
    };
    if y >= rows || needle.is_empty() || needle.len() > cols {
        return false;
    }
    for x in 0..=cols - needle.len() {
        let mut holds = true;
        for (i, want) in needle.iter().enumerate() {
            match crate::vga::peek_cell(x + i, y) {
                Some((glyph, _)) if glyph == *want => {}
                _ => {
                    holds = false;
                    break;
                }
            }
        }
        if holds {
            return true;
        }
    }
    false
}

/// Does any cell of row `y` of the actual text buffer carry `attr`?
fn row_holds_attr(y: usize, attr: u8) -> bool {
    let Some((cols, rows)) = screen::dims() else {
        return false;
    };
    if y >= rows {
        return false;
    }
    (0..cols).any(|x| crate::vga::peek_cell(x, y).is_some_and(|(_, a)| a == attr))
}

// ---------------------------------------------------------------------------
// The `tui` builtin: interactive session
// ---------------------------------------------------------------------------

/// The `tui` shell builtin: draw the demo frame and navigate it with
/// the polled keyboard until `Esc`. Fails soft — no text console or a
/// render error prints one line and returns to the prompt; when the
/// frame did reach the screen, the text buffer is cleared on exit so
/// the shell resumes on a clean screen.
pub fn run() {
    if let Err(why) = screen::open() {
        serial_println!("tui: {why}");
        return;
    }
    if session() {
        crate::vga::clear_screen();
    }
}

/// One interactive session. Returns whether any frame reached the
/// screen (only then is the screen cleared on exit).
fn session() -> bool {
    let mut state = ListState::default().with_selected(Some(0));
    let mut terminal = match Terminal::new(VgaBackend::default()) {
        Ok(terminal) => terminal,
        Err(why) => {
            serial_println!("tui: {why}");
            return false;
        }
    };
    // First frame — if it fails, nothing was flushed and the shell's
    // screen is still intact (return false: don't clear it).
    if let Err(why) = terminal.draw(|frame| render(frame, &mut state)) {
        serial_println!("tui: render failed ({why})");
        return false;
    }
    loop {
        let key = next_key();
        match key {
            Key::Esc => break,
            Key::Up | Key::Down => {
                move_selection(&mut state, key == Key::Down);
                if let Err(why) = terminal.draw(|frame| render(frame, &mut state)) {
                    serial_println!("tui: render failed ({why})");
                    break;
                }
            }
            // Characters and the unmapped keys do nothing in the demo.
            _ => {}
        }
    }
    true
}

/// Block until a key arrives: the polled PS/2 keyboard first, with a
/// serial fallback so a headless terminal can still `Esc` out.
///
/// Serial input maps only whole ASCII bytes (`Esc`, `Enter`,
/// `Backspace`, printable) — ANSI cursor sequences (`ESC [ A`) are
/// *not* parsed, so an arrow typed over serial quits the app; arrows
/// live on the PS/2 path (`keyboard::next_event`), which is what
/// `cargo xtask run`'s `sendkey` drives. Documented limit.
fn next_key() -> Key {
    loop {
        if let Some(key) = crate::keyboard::next_event() {
            return key;
        }
        if let Some(byte) = crate::serial::SerialPort::COM1.read_byte()
            && let Some(key) = serial_key(byte)
        {
            return key;
        }
        core::hint::spin_loop();
    }
}

fn serial_key(byte: u8) -> Option<Key> {
    match byte {
        0x1B => Some(Key::Esc),
        b'\r' | b'\n' => Some(Key::Enter),
        0x08 | 0x7F => Some(Key::Backspace),
        b if b.is_ascii_graphic() || b == b' ' => Some(Key::Char(char::from(b))),
        _ => None, // other control bytes and CSI leftovers: ignored
    }
}
