//! Milestone A2 (docs/ai-client.md §5, §7): the in-memory text editor.
//!
//! - Buffer: [`editorbuf::Buffer`] — the from-scratch gap buffer with
//!   its own adversarial host suite (exceptions (a)+(b), recorded in
//!   §5 and in that crate's docs).
//! - Rendering: through A1's screen layer via [`VgaBackend`] — the
//!   *same* ratatui path `apps::tui` uses (one rendering path for the
//!   whole apps layer, no fork). Line-number gutter + text viewport
//!   (cursor-following scroll, arrows and PgUp/PgDn), reverse-video
//!   cursor cell, status bar with `line:col`, the modified flag and the
//!   discoverable key list.
//! - [`boot_proof`]: the scripted `EDITOR_OK` proof (insert → newline →
//!   delete → undo → redo → render → read back from `0xb8000`), run
//!   between `TUI_OK` and `SHELL_OK`. Fail-closed: `FATAL:` + `halt()`.
//! - [`run`]: the `edit` shell builtin's interactive loop (Esc quits,
//!   screen self-heals like `tui`'s).
//!
//! # Scope: no filesystem, no network (deferred, not stubbed)
//!
//! Open/save need the filesystem milestone (installer/fat32); they are
//! deliberately absent — there are **no fake stubs** here. The buffer
//! starts from an in-memory [`SAMPLE`] and lives only for the session.
//! No network path exists in this milestone either.
//!
//! # Key map (also shown in the status bar)
//!
//! | Key | Action |
//! |---|---|
//! | printable | insert at the cursor |
//! | `Enter` | split the line |
//! | `Backspace` | delete the whole UTF-8 scalar before the cursor |
//! | arrows / `Home` / `End` | move (clamped to line ends / buffer) |
//! | `PgUp` / `PgDown` | move the cursor one screenful of lines |
//! | `Tab` / `Ctrl-U` | undo |
//! | `Delete` / `Ctrl-R` | redo |
//! | `Esc` | quit back to the shell prompt |
//!
//! **Why not `Ctrl-U`/`Ctrl-R` on the keyboard, or F5?** Verified in
//! `pc-keyboard` 0.9: with the decoder configured `HandleControl::Ignore`
//! (keyboard.rs), Ctrl+letter folds back into the plain letter, F-keys
//! decode to `RawKey` codes that [`crate::keyboard::next_event`] does not
//! map (it returns `None`), and `Key` has no Ctrl/F5 variant at all.
//! Adding one would change `keyboard.rs`'s frozen semantics (A2 must
//! consume it, not modify it). So undo/redo live on `Tab`/`Delete` —
//! the two keys no standard editor binding needs — and the *serial*
//! console additionally accepts the spec's `Ctrl-U` (0x15) / `Ctrl-R`
//! (0x12) bytes, which arrive as raw bytes there. Over serial,
//! `Del`-less terminals can redo with Ctrl-R; `0x7F` stays Backspace
//! (terminal convention).

use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use crate::keyboard::Key;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use editorbuf::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

/// The in-memory sample buffer: a short Rust-ish snippet that shows
/// off the line-number gutter. Open/save land with the filesystem
/// milestone (module docs) — this is the *only* way a buffer comes
/// into existence today. One line on purpose: a `\`-continuation would
/// strip the indentation (and with it `ANSWER_OFFSET`'s anchor).
const SAMPLE: &str = "// reemplazo editor A2 - in-memory buffer (open/save: FS milestone)\nfn main() {\n    let answer = 0;\n}\n";

/// Byte offset of the sample's `0` value within line 2
/// (`"    let answer = "` = 4 + 13). The proof inserts `42` in front
/// of it (line becomes `420`), then step (c) deletes the stray `0`
/// (→ `42;`) — insert and delete both land on this line.
const ANSWER_OFFSET: usize = 17;

/// Status bar style (white on blue), as the VGA attribute byte the boot
/// proof asserts: fg 15 | bg 4 << 4 (same encoding as `tui`'s).
const STATUS_ATTR: u8 = 0x4F;
/// Smallest geometry the boot proof needs: gutter (4) + the longest
/// sample line (`let answer = 42;` = 20) and six rows (five text lines
/// + status). GRUB leaves 80×25.
const MIN_COLS: usize = 30;
const MIN_ROWS: usize = 6;

// ---------------------------------------------------------------------------
// Editor state
// ---------------------------------------------------------------------------

/// One input event for the editor: a [`Key`] from
/// [`crate::keyboard::next_event`], or an undo/redo request (the serial
/// console's raw `Ctrl-U`/`Ctrl-R` bytes have no `Key` variant — see the
/// module docs' key map).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EdKey {
    Key(Key),
    Undo,
    Redo,
}

/// Everything one editor session owns. All of it lives in ordinary
/// struct fields on the calling stack (a few hundred bytes); the large
/// buffers — ratatui's two frames and the `Buffer` text — are heap
/// allocations (the boot stack is far too small for those, and the
/// screen layer itself is A1's `static mut`).
struct Editor {
    buf: Buffer,
    /// Byte offset into `buf` — always a char boundary, always ≤ len
    /// (re-validated by [`Editor::clamp_cursor`] after every history
    /// replay, which can remove bytes from under the cursor).
    cursor: usize,
    /// First buffer line shown in the viewport.
    scroll_row: usize,
    /// First *character column* shown (text mode: every glyph is one
    /// cell, see `screen::glyph` — so char index == display column).
    scroll_col: usize,
    /// Last rendered viewport size (for PgUp/PgDown before/after draws).
    view_h: usize,
    view_w: usize,
    /// Reused per-line byte scratch (heap-backed `Vec`, never the boot
    /// stack).
    scratch: Vec<u8>,
}

impl Editor {
    /// The session buffer: the in-memory [`SAMPLE`], cursor at the top.
    fn sample() -> Self {
        Self {
            // The sample is a const far under `MAX_BYTES`, so this
            // cannot fail; `unwrap_or_default` keeps the constructor
            // panic-free regardless — and an empty buffer would fail
            // the boot proof loudly on its missing line 2.
            buf: Buffer::from_text(SAMPLE).unwrap_or_default(),
            cursor: 0,
            scroll_row: 0,
            scroll_col: 0,
            view_h: 0,
            view_w: 0,
            scratch: Vec::new(),
        }
    }

    /// Apply one input event. Returns whether the state changed (the
    /// caller redraws only then). History replays re-validate the
    /// cursor: undo/redo can shift content underneath it.
    fn handle(&mut self, key: EdKey) -> bool {
        let changed = match key {
            EdKey::Undo => self.buf.undo(),
            EdKey::Redo => self.buf.redo(),
            EdKey::Key(key) => self.handle_key(key),
        };
        if changed {
            self.clamp_cursor();
        }
        changed
    }

    fn handle_key(&mut self, key: Key) -> bool {
        match key {
            Key::Char(c) => {
                let mut storage = [0u8; 4];
                let text = c.encode_utf8(&mut storage);
                self.try_insert(text)
            }
            Key::Enter => self.try_insert("\n"),
            Key::Backspace => {
                // Char-aware: remove the whole scalar before the cursor
                // (at a line start that scalar is the `\n`, merging the
                // lines — the natural editor behaviour).
                let Some(prev) = self.buf.prev_boundary(self.cursor) else {
                    return false;
                };
                if self.buf.remove(prev, self.cursor - prev).is_ok() {
                    self.cursor = prev;
                    true
                } else {
                    false
                }
            }
            Key::Left => match self.buf.prev_boundary(self.cursor) {
                Some(prev) => {
                    self.cursor = prev;
                    true
                }
                None => false, // at the buffer start
            },
            Key::Right => match self.buf.next_boundary(self.cursor) {
                Some(next) => {
                    self.cursor = next;
                    true
                }
                None => false, // at the buffer end
            },
            Key::Up => self.move_vert(true),
            Key::Down => self.move_vert(false),
            Key::Home => {
                let line = self.buf.line_of(self.cursor).unwrap_or(0);
                match self.buf.line_start(line) {
                    Some(start) if start != self.cursor => {
                        self.cursor = start;
                        true
                    }
                    _ => false,
                }
            }
            Key::End => {
                let line = self.buf.line_of(self.cursor).unwrap_or(0);
                match self.buf.line_end(line) {
                    Some(end) if end != self.cursor => {
                        self.cursor = end;
                        true
                    }
                    _ => false,
                }
            }
            Key::PageUp => self.page(false),
            Key::PageDown => self.page(true),
            // Esc quits in `session` before reaching here; Tab and
            // Delete are mapped to Undo/Redo in `next_key`.
            _ => false,
        }
    }

    fn try_insert(&mut self, text: &str) -> bool {
        if self.buf.insert(self.cursor, text).is_ok() {
            // Inserted at the cursor, which was a boundary, so
            // cursor + text.len() is a boundary too.
            self.cursor = self.cursor.saturating_add(text.len());
            true
        } else {
            false // buffer at MAX_BYTES: fail soft, keep editing
        }
    }

    /// Move one line up/down keeping the character column (clamped to
    /// the shorter line's end — [`Buffer::line_offset_for_char`]).
    fn move_vert(&mut self, up: bool) -> bool {
        let line = self.buf.line_of(self.cursor).unwrap_or(0);
        let target = if up {
            line.checked_sub(1)
        } else {
            let next = line.saturating_add(1);
            (next < self.buf.line_count()).then_some(next)
        };
        match target {
            Some(target) => self.jump_to_line(target),
            None => false,
        }
    }

    /// Move the cursor to `target` line, same character column.
    fn jump_to_line(&mut self, target: usize) -> bool {
        let col = self.buf.char_index(self.cursor).unwrap_or(0);
        let Some(at) = self.buf.line_offset_for_char(target, col) else {
            return false;
        };
        if at == self.cursor {
            return false;
        }
        self.cursor = at;
        true
    }

    /// PgUp/PgDown: one viewport of lines (falls back to a single line
    /// before the first frame has sized the viewport).
    fn page(&mut self, forward: bool) -> bool {
        let count = self.buf.line_count();
        let line = self.buf.line_of(self.cursor).unwrap_or(0);
        let step = self.view_h.max(1);
        let target = if forward {
            line.saturating_add(step).min(count.saturating_sub(1))
        } else {
            line.saturating_sub(step)
        };
        self.jump_to_line(target)
    }

    /// Keep the cursor inside the buffer and on a char boundary.
    /// Undo/redo replays can delete bytes from under the cursor (the
    /// same offset then points *inside* a scalar), so the boundary is
    /// re-checked after every history operation, not just clamped.
    fn clamp_cursor(&mut self) {
        let len = self.buf.len();
        if self.cursor > len {
            self.cursor = len;
            return;
        }
        if self.cursor > 0 && !self.buf.is_boundary(self.cursor) {
            // Snap back to the start of the scalar now under the cursor.
            self.cursor = self.buf.prev_boundary(self.cursor).unwrap_or(0);
        }
    }

    /// Scroll so the cursor's line and column are inside the viewport.
    fn ensure_visible(&mut self) {
        let count = self.buf.line_count();
        let cursor_line = self.buf.line_of(self.cursor).unwrap_or(0);
        let view_h = self.view_h.max(1);
        if cursor_line < self.scroll_row {
            self.scroll_row = cursor_line;
        } else if cursor_line >= self.scroll_row.saturating_add(view_h) {
            // cursor_line ≥ scroll_row + view_h ≥ view_h, no underflow.
            self.scroll_row = cursor_line + 1 - view_h;
        }
        let text_w = self.view_w.saturating_sub(gutter_width(count) + 1);
        let cursor_char = self.buf.char_index(self.cursor).unwrap_or(0);
        if cursor_char < self.scroll_col {
            self.scroll_col = cursor_char;
        } else if text_w > 0 && cursor_char >= self.scroll_col.saturating_add(text_w) {
            self.scroll_col = cursor_char + 1 - text_w;
        }
    }

    /// Build the viewport as ratatui lines: gutter span + text span,
    /// with the cursor cell reverse-video when it is on the line.
    fn viewport_text(&mut self) -> Text<'static> {
        let count = self.buf.line_count();
        let gutter = gutter_width(count);
        let text_w = self.view_w.saturating_sub(gutter + 1);
        let cursor_line = self.buf.line_of(self.cursor).unwrap_or(0);
        let cursor_char = self.buf.char_index(self.cursor).unwrap_or(0);
        let gutter_style = Style::new().fg(Color::DarkGray);
        let mut lines: Vec<Line<'static>> = Vec::with_capacity(self.view_h);
        for row in 0..self.view_h {
            let line_no = self.scroll_row.saturating_add(row);
            if line_no >= count {
                lines.push(Line::from(""));
                continue;
            }
            let number = line_no + 1;
            let label = format!("{number:>gutter$} ");
            // `line_bytes` clears and fills the scratch; the buffer is
            // valid UTF-8 by construction (editorbuf's contract), so
            // the `Err` arm is unreachable — `""` degrades to a blank
            // line instead of panicking.
            if !self.buf.line_bytes(line_no, &mut self.scratch) {
                lines.push(Line::from(""));
                continue;
            }
            let full = core::str::from_utf8(&self.scratch).unwrap_or("");
            let shown: String = full.chars().skip(self.scroll_col).take(text_w).collect();
            if line_no == cursor_line && cursor_char >= self.scroll_col {
                let pos = cursor_char - self.scroll_col;
                let chars: Vec<char> = shown.chars().collect();
                // `get(pos)` past the end (cursor on the line end)
                // renders as a reversed space — one branch, no indexing.
                let head: String = chars.iter().take(pos).collect();
                let at: String = chars.get(pos).copied().unwrap_or(' ').to_string();
                let tail: String = chars.iter().skip(pos + 1).collect();
                lines.push(Line::from(vec![
                    Span::styled(label, gutter_style),
                    Span::raw(head),
                    Span::styled(at, Style::new().add_modifier(Modifier::REVERSED)),
                    Span::raw(tail),
                ]));
            } else {
                lines.push(Line::from(vec![
                    Span::styled(label, gutter_style),
                    Span::raw(shown),
                ]));
            }
        }
        Text::from(lines)
    }

    /// Status bar: position, modified flag, and the discoverable key
    /// list (fits80 columns; longer screens just have slack).
    fn status_text(&self) -> String {
        let line = self.buf.line_of(self.cursor).unwrap_or(0) + 1;
        let col = self.buf.char_index(self.cursor).unwrap_or(0) + 1;
        let flag = if self.buf.modified() { " [+]" } else { "" };
        format!(
            "Ln {line},Col {col}{flag}  arrows/PgUp/PgDn move · \
             Tab/C-u undo · Del/C-r redo · Esc quit"
        )
    }

    /// Render one full frame: text viewport on top, status bar on the
    /// last row. Geometry comes from `Frame::area()` (the live text
    /// geometry) — never a hardcoded 80×25.
    fn render_into(&mut self, frame: &mut Frame) {
        let area = frame.area();
        let Some(text_h) = area.height.checked_sub(1) else {
            return;
        };
        if text_h == 0 || area.width < 8 {
            return; // degenerate geometry: draw nothing, never panic
        }
        self.view_h = usize::from(text_h);
        self.view_w = usize::from(area.width);
        self.ensure_visible();
        let text_area = Rect::new(area.x, area.y, area.width, text_h);
        let text = self.viewport_text();
        frame.render_widget(Paragraph::new(text), text_area);
        let status_area = Rect::new(area.x, area.y.saturating_add(text_h), area.width, 1);
        let status =
            Paragraph::new(self.status_text()).style(Style::new().fg(Color::White).bg(Color::Blue));
        frame.render_widget(status, status_area);
    }
}

/// Gutter width: right-aligned line numbers in at least 3 columns
/// (plus the separator space, added by the caller's `label`).
fn gutter_width(line_count: usize) -> usize {
    let mut digits = 1usize;
    let mut rest = line_count;
    while rest >= 10 {
        rest /= 10;
        digits += 1;
    }
    digits.max(3)
}

// ---------------------------------------------------------------------------
// The boot proof: EDITOR_OK
// ---------------------------------------------------------------------------

/// Script the A2 proof: build the sample buffer, apply a deterministic
/// insert / newline / delete / **undo / redo** sequence, render the
/// frame, flush it, then read it back from `0xb8000` and assert the
/// gutter, the edited line and the status bar are really on screen —
/// the smoke test's `EDITOR_OK` (printed between `TUI_OK` and
/// `SHELL_OK`). On any mismatch: `FATAL:` + [`crate::halt`], like every
/// other boot proof; a genuinely absent text console just skips the
/// proof (the same way `TUI_OK` does). Afterwards the screen is cleared
/// and the console cursor reset, so the shell starts clean — serial
/// output is never reordered or suppressed.
pub fn boot_proof() {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: editor: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove() {
        serial_println!("FATAL: editor: {why}");
        crate::halt();
    }
    serial_println!("EDITOR_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// The scripted edit sequence plus the `0xb8000` readback. Fail-closed:
/// every error string becomes a `FATAL:` line.
fn prove() -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the editor frame (min 30x6)");
    }
    let mut ed = Editor::sample();

    // (a) insert text: `42` in front of the sample's `0` value, so
    // line 2 temporarily reads `let answer = 420;`
    let base = ed.buf.line_start(2).ok_or("sample line 2 missing")?;
    let at = base
        .checked_add(ANSWER_OFFSET)
        .ok_or("line-2 offset overflow")?;
    ed.buf
        .insert(at, "42")
        .map_err(|_| "insert of \"42\" refused")?;

    // (b) newline: a new line (the println) before the closing brace
    let brace = ed.buf.line_start(3).ok_or("sample line 3 missing")?;
    ed.buf
        .insert(brace, "    println!(\"{answer}\");\n")
        .map_err(|_| "newline insert refused")?;

    // (c) delete: drop the now-stray `0` (the value widened by two
    // bytes in step (a)) → `let answer = 42;`
    let zero_at = base
        .checked_add(ANSWER_OFFSET)
        .and_then(|at| at.checked_add("42".len()))
        .ok_or("stray-zero offset overflow")?;
    ed.buf
        .remove(zero_at, 1)
        .map_err(|_| "stray-zero delete refused")?;

    // Undo (c): the `0` comes back byte-exact …
    if !ed.buf.undo() {
        return Err("undo returned false");
    }
    if !line_starts_with(&ed.buf, 2, b"    let answer = 420;") {
        return Err("undo did not restore the deleted zero");
    }
    // … and redo (c) removes it again: both directions really replay
    // history, not just "an edit happened".
    if !ed.buf.redo() {
        return Err("redo returned false");
    }
    if !line_starts_with(&ed.buf, 2, b"    let answer = 42;") {
        return Err("redo did not reapply the deletion");
    }
    ed.clamp_cursor();

    // Render through the A1 path (ratatui → VgaBackend → screen diff →
    // `0xb8000`) and verify what the text buffer really holds.
    let mut terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
    terminal
        .draw(|frame| ed.render_into(frame))
        .map_err(|_| "editor frame failed")?;

    // Gutter: right-aligned `1` and `3` with the separator space, read
    // back from the real cells (row 0 = sample line 0, row 2 = the
    // edited `let answer = 42;` line — viewport starts at line 1).
    let gutter = gutter_width(ed.buf.line_count());
    if !cells_hold(0, 0, gutter_cell(1, gutter).as_bytes()) {
        return Err("line-number gutter missing on row 0");
    }
    if !cells_hold(0, 2, gutter_cell(3, gutter).as_bytes()) {
        return Err("line-number gutter missing on row 2");
    }
    if !row_holds(2, b"let answer = 42;") {
        return Err("edited line missing from row 2");
    }
    if !row_holds(3, b"println!(\"{answer}\");") {
        return Err("inserted line missing from row 3");
    }
    let status_row = rows.checked_sub(1).ok_or("no status row")?;
    if !row_holds(status_row, b"Esc quit") {
        return Err("status bar missing from the last row");
    }
    if !row_holds(status_row, b"[+]") {
        return Err("modified flag missing from the status bar");
    }
    if !row_holds_attr(status_row, STATUS_ATTR) {
        return Err("status attribute missing from the last row");
    }
    Ok(())
}

/// Does line `line` of `buf` start with `prefix`? (The proof's
/// undo/redo content assertion — buffer level, before any rendering.)
fn line_starts_with(buf: &Buffer, line: usize, prefix: &[u8]) -> bool {
    let mut out = Vec::new();
    buf.line_bytes(line, &mut out) && out.starts_with(prefix)
}

/// The gutter cell text the render draws for `number`: right-aligned in
/// `gutter` columns plus the separator space.
fn gutter_cell(number: usize, gutter: usize) -> String {
    format!("{number:>gutter$} ")
}

/// Does row `y` of the *actual* text buffer hold `needle` as
/// consecutive glyph bytes? (The `VGA_OK`/`TUI_OK` readback style.)
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

/// Does row `y` start (at column `x`) with exactly `needle`? Used for
/// the gutter, whose column position is part of the assertion.
fn cells_hold(x: usize, y: usize, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return false;
    }
    needle.iter().enumerate().all(
        |(i, want)| matches!(crate::vga::peek_cell(x + i, y), Some((glyph, _)) if glyph == *want),
    )
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
// The `edit` builtin: interactive session
// ---------------------------------------------------------------------------

/// The `edit` shell builtin: open the in-memory sample buffer and edit
/// it with the polled keyboard until `Esc`. Fails soft — no text
/// console or a render error prints one line and returns to the
/// prompt; when a frame did reach the screen, the text buffer is
/// cleared on exit so the shell resumes on a clean screen (same
/// contract as `tui`).
pub fn run() {
    if let Err(why) = screen::open() {
        serial_println!("editor: {why}");
        return;
    }
    if session() {
        crate::vga::clear_screen();
    }
}

/// One interactive session. Returns whether any frame reached the
/// screen (only then is the screen cleared on exit).
fn session() -> bool {
    let mut ed = Editor::sample();
    let mut terminal = match Terminal::new(VgaBackend::default()) {
        Ok(terminal) => terminal,
        Err(why) => {
            serial_println!("editor: {why}");
            return false;
        }
    };
    // First frame — if it fails, nothing was flushed and the shell's
    // screen is still intact (return false: don't clear it).
    if let Err(why) = terminal.draw(|frame| ed.render_into(frame)) {
        serial_println!("editor: render failed ({why})");
        return false;
    }
    loop {
        match next_key() {
            EdKey::Key(Key::Esc) => break,
            key => {
                if ed.handle(key)
                    && let Err(why) = terminal.draw(|frame| ed.render_into(frame))
                {
                    serial_println!("editor: render failed ({why})");
                    break;
                }
            }
        }
    }
    true
}

/// Block until a key arrives: the polled PS/2 keyboard first, with a
/// serial fallback so a headless terminal can still drive the editor.
///
/// The keyboard path maps `Tab`→Undo and `Delete`→Redo (module docs:
/// `Key` exposes no Ctrl/F-key events). The serial path maps the raw
/// `Ctrl-U`/`Ctrl-R` bytes (0x15/0x12) to the same operations and `Tab`
/// (0x09) too; `0x7F` stays Backspace (terminal convention), and ANSI
/// cursor sequences (`ESC [ A`) are *not* parsed — an arrow typed over
/// serial quits the app, arrows live on the PS/2 path
/// (`keyboard::next_event`), which is what `cargo xtask run`'s
/// `sendkey` drives. Documented limit (same as `tui`'s).
fn next_key() -> EdKey {
    loop {
        if let Some(key) = crate::keyboard::next_event() {
            return match key {
                Key::Tab => EdKey::Undo,
                Key::Delete => EdKey::Redo,
                other => EdKey::Key(other),
            };
        }
        if let Some(byte) = crate::serial::SerialPort::COM1.read_byte()
            && let Some(key) = serial_key(byte)
        {
            return key;
        }
        core::hint::spin_loop();
    }
}

fn serial_key(byte: u8) -> Option<EdKey> {
    match byte {
        0x1B => Some(EdKey::Key(Key::Esc)),
        b'\r' | b'\n' => Some(EdKey::Key(Key::Enter)),
        0x08 | 0x7F => Some(EdKey::Key(Key::Backspace)),
        0x09 | 0x15 => Some(EdKey::Undo), // Tab, Ctrl-U
        0x12 => Some(EdKey::Redo),        // Ctrl-R
        b if b.is_ascii_graphic() || b == b' ' => Some(EdKey::Key(Key::Char(char::from(b)))),
        _ => None, // other control bytes and CSI leftovers: ignored
    }
}
