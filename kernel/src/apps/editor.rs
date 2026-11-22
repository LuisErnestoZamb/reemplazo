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
//! # Milestone A5: the retained document (editor ↔ AI)
//!
//! One **retained document** outlives `edit` sessions: the buffer plus
//! caret live in a module [`static`] ([`DOC`]) instead of being dropped
//! on `Esc`. [`Editor::mount`] takes it out for a session (the in-memory
//! [`SAMPLE`] on first use — the pre-A5 behaviour) and
//! [`Editor::unmount`] gives it back, so `Esc` *saves* the session into
//! the document rather than discarding it. Two operations then work on
//! the resident document without opening the editor:
//!
//! - [`quote_cursor_line`] — the document's cursor line, the context an
//!   `ai apply` request quotes (the "quote the buffer" half of A5),
//! - [`apply_completion`] — insert a model completion at the cursor
//!   through the same `insert_at` primitive typing uses, so it records
//!   **one undo entry** and the editor's undo (Tab / Ctrl-U) removes
//!   exactly that completion.
//!
//! The SAFETY contract of the `static mut` follows the repo idiom (the
//! `screen.rs`/`tls.rs` single-consumer rule): one core, boot proof
//! before `shell::run`, and the shell serves `edit` / `ai apply`
//! sequentially — each entry point takes the document for one short
//! operation and gives it back; IRQ0 never touches this module.
//! [`ai_edit_boot_proof`] wires that document to A3's mock exchange and
//! proves the whole loop (`AI_EDIT_OK`, between `AI_CHAT_OK` and
//! `SHELL_OK`).
//!
//! # Scope: no filesystem, no network (deferred, not stubbed)
//!
//! Open/save need the filesystem milestone (installer/fat32); they are
//! deliberately absent — there are **no fake stubs** here. The buffer
//! starts from an in-memory [`SAMPLE`] and lives only in the retained
//! document (RAM) for the session. The network path exists only as A5's
//! quote/apply pair over the A3 mock — a real endpoint is milestone A4.
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

use crate::apps::ai;
use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use crate::keyboard::Key;
use crate::netstack::Stack;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ptr::addr_of_mut;
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
// Milestone A5: the retained document
// ---------------------------------------------------------------------------

/// The A5 seed text: what the retained document holds when
/// [`ai_edit_boot_proof`] starts (and the only way `SEED` ever enters
/// the document — a fresh `edit` before the proof ran falls back to
/// [`SAMPLE`]). The cursor is parked at the **end of line 2** — the
/// insertion point — which ends with a space so the applied completion
/// reads as its own word (the mock reply is canned and carries no
/// leading space). Line 2's `// TODO: ask AI` stays byte-identical
/// through the apply, which is what the readback asserts.
const SEED: &str =
    "// reemplazo A5 - editor <-> AI\nfn main() {\n    let answer = 0; // TODO: ask AI \n}\n";
/// Byte offset of the insertion point within [`SEED`]: right after the
/// trailing space of line 2 (the `\n` that closes it follows). Found
/// structurally by [`seed_document`], pinned here as a cross-check.
const SEED_CURSOR: usize = SEED.len() - "\n}\n".len();
/// Smallest geometry the A5 proof needs: gutter (4) + the longest
/// rendered row (the seed line + the canned reply = 60) and six rows
/// (five text lines + status).
const AI_MIN_COLS: usize = 64;
const AI_MIN_ROWS: usize = 6;
/// Bound on the line quoted into an `ai apply` request (bytes, cut at a
/// char boundary): a 1 MiB line must not become a 1 MiB request body
/// (docs/ai-client.md §8 — bounded memory).
const QUOTE_CAP: usize = 96;

/// One retained document: the buffer plus the caret that outlive an
/// `edit` session (module docs — A5).
struct Doc {
    buf: Buffer,
    /// Byte offset into `buf` — always a char boundary, ≤ len (the same
    /// contract as [`Editor::cursor`], re-validated on mount after any
    /// history replay).
    cursor: usize,
}

/// The one open document: `None` until the first `edit` or the
/// [`ai_edit_boot_proof`] seed creates it. SAFETY contract (the repo's
/// `static mut` idiom, as `screen.rs`/`tls.rs`): **single consumer** on
/// one core — the boot proof runs before `shell::run`, and the shell
/// serves `edit` / `ai apply` sequentially, each taking the document for
/// one short operation via [`doc_mut`]/[`doc_ref`] and giving it back;
/// IRQ0 (PIT) never touches this module, so no handler can alias the
/// references handed out here. The payload is heap-backed, so the static
/// itself is a small `Option`.
static mut DOC: Option<Doc> = None;

/// Exclusive access to the retained document — the single-consumer
/// boundary (see [`DOC`]'s SAFETY note).
fn doc_mut() -> &'static mut Option<Doc> {
    // SAFETY: raw-pointer deref of the `static mut` whose access
    // contract is [`DOC`]'s; callers take it for one short operation at
    // a time and never hold two of these at once.
    unsafe { &mut *addr_of_mut!(DOC) }
}

/// Shared access to the retained document (read paths that must not
/// alias a live `&mut`, e.g. [`quote_cursor_line`]).
fn doc_ref() -> &'static Option<Doc> {
    // SAFETY: read-only side of [`DOC`]'s single-consumer contract.
    unsafe { &*core::ptr::addr_of!(DOC) }
}

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

    /// Mount the retained document into this session (A5): buffer and
    /// caret from [`DOC`], fresh view state. First use — no document
    /// yet — falls back to the in-memory [`SAMPLE`], exactly the
    /// pre-A5 behaviour.
    fn mount() -> Self {
        match doc_mut().take() {
            Some(doc) => Self {
                buf: doc.buf,
                cursor: doc.cursor,
                scroll_row: 0,
                scroll_col: 0,
                view_h: 0,
                view_w: 0,
                scratch: Vec::new(),
            },
            None => Self::sample(),
        }
    }

    /// Give the document back to [`DOC`] — the `Esc` "save" path (A5):
    /// the session's buffer and caret survive into the next `edit` and
    /// are what `ai apply` inserts into afterwards.
    fn unmount(&mut self) {
        *doc_mut() = Some(Doc {
            buf: core::mem::take(&mut self.buf),
            cursor: self.cursor,
        });
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
        insert_at(&mut self.buf, &mut self.cursor, text)
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

// ---------------------------------------------------------------------------
// Milestone A5: document operations (retained document)
// ---------------------------------------------------------------------------

/// Insert `text` at `cursor` inside `buf`, advancing `cursor` past it —
/// **one** implementation shared by ordinary typing ([`Editor::try_insert`])
/// and A5's completion apply ([`apply_completion`], [`seed_document`]'s
/// proof): `Buffer::insert` refuses non-char-boundary offsets and inserts
/// past `MAX_BYTES`, so UTF-8 safety and the byte cap stay editorbuf's
/// (this only decides "cursor advances or the edit fails soft").
fn insert_at(buf: &mut Buffer, cursor: &mut usize, text: &str) -> bool {
    if buf.insert(*cursor, text).is_ok() {
        // Inserted at a boundary, so cursor + text.len() is one too.
        *cursor = (*cursor).saturating_add(text.len());
        true
    } else {
        false // buffer at MAX_BYTES: fail soft, keep editing
    }
}

/// A5's "quote the buffer": the retained document's cursor line, the
/// context an `ai apply` request carries. `None` when no document is
/// open yet (nothing to quote). The line is cut to [`QUOTE_CAP`] bytes
/// at a char boundary — a huge line cannot become a huge request.
pub fn quote_cursor_line() -> Option<String> {
    let doc = doc_ref().as_ref()?;
    let line = doc.buf.line_of(doc.cursor).unwrap_or(0);
    let mut bytes = Vec::new();
    if !doc.buf.line_bytes(line, &mut bytes) {
        return Some(String::new());
    }
    // editorbuf guarantees valid UTF-8, so this is the whole line;
    // `unwrap_or("")` keeps the quote panic-free regardless.
    let text = core::str::from_utf8(&bytes).unwrap_or("");
    let mut head = String::new();
    for (i, ch) in text.char_indices() {
        if i >= QUOTE_CAP {
            break; // `i` is a char start, so the cut stays on a boundary
        }
        head.push(ch);
    }
    Some(head)
}

/// A5's apply operation: insert a model completion `text` at the
/// retained document's cursor, through [`insert_at`] — so the edit
/// lands in `editorbuf`'s undo history exactly like typed text and the
/// editor's undo (Tab / Ctrl-U) removes precisely this completion.
/// `Err` (fail-soft, shell contract) when no document is open or the
/// buffer refused the insert; in both cases nothing is modified.
pub fn apply_completion(text: &str) -> Result<(), &'static str> {
    let doc = doc_mut().as_mut().ok_or("no open document")?;
    if insert_at(&mut doc.buf, &mut doc.cursor, text) {
        Ok(())
    } else {
        Err("insert refused (buffer full)")
    }
}

/// Put [`SEED`] into the retained document with the caret at the
/// insertion point ([`SEED_CURSOR`], cross-checked against the buffer's
/// own line index so the two cannot drift apart).
fn seed_document() -> Result<(), &'static str> {
    let buf = Buffer::from_text(SEED).map_err(|_| "seed text refused")?;
    let cursor = buf.line_end(2).ok_or("seed line 2 missing")?;
    if cursor != SEED_CURSOR {
        return Err("seed insertion point drifted");
    }
    *doc_mut() = Some(Doc { buf, cursor });
    Ok(())
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
// The boot proof: AI_EDIT_OK (milestone A5)
// ---------------------------------------------------------------------------

/// Script the A5 proof — the "opencode-like" loop end to end: seed the
/// retained document ([`SEED`]), quote its cursor line into **one real
/// mock exchange** (A3's transport, sanitizing both directions), apply
/// the reply at the document's cursor through the same path `ai apply`
/// uses, prove the **undo/redo round-trip** at buffer level, render the
/// editor frame and read it back from `0xb8000` — the smoke test's
/// `AI_EDIT_OK` (printed between `AI_CHAT_OK` and `SHELL_OK`).
///
/// Fail-closed like every other boot proof, with the failure domain in
/// the prefix: the exchange and the reply content fail as `FATAL: ai:`,
/// the document, undo trail and screen as `FATAL: editor:`. A genuinely
/// absent text console skips the proof (the `TUI_OK` rule), and — like
/// `ai::boot_proof` — it needs the network stack, which
/// [`crate::kernel_main`] guarantees by only calling this inside its
/// `Some(stack)` branch (the smoke always has a NIC, so a skip shows up
/// as a missing marker). Afterwards the screen is cleared and the
/// console cursor reset, so the shell starts clean — and the retained
/// document is left **with the completion applied**, which is what the
/// next `edit` / `ai apply` session works on.
pub fn ai_edit_boot_proof(stack: &mut Stack) {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: editor: {why}");
            crate::halt();
        }
    }
    if let Err(why) = seed_document() {
        serial_println!("FATAL: editor: {why}");
        crate::halt();
    }
    // The quote comes from the resident document (A5's "quote the
    // buffer"); no document after the seed above is a logic bug.
    let Some(context) = quote_cursor_line() else {
        serial_println!("FATAL: editor: seeded document is not resident");
        crate::halt();
    };
    // A3's exchange + sanitizing path (`ai::one_shot`): transport and
    // reply text are untrusted, and the content must be the canned mock
    // answer — a 200 carrying anything else fails as loudly as a
    // transport error would.
    let reply = match ai::one_shot(stack, &context) {
        Ok(reply) => reply,
        Err(why) => {
            serial_println!("FATAL: ai: {why}");
            crate::halt();
        }
    };
    if !ai::is_canned(&reply) {
        serial_println!("FATAL: ai: mock reply content mismatch");
        crate::halt();
    }
    if let Err(why) = prove_ai_edit(&reply) {
        serial_println!("FATAL: editor: {why}");
        crate::halt();
    }
    serial_println!("AI_EDIT_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// The document/render half of [`ai_edit_boot_proof`]: mount the seeded
/// document, apply the completion at the cursor, assert the buffer
/// through one undo **and** redo (both directions really replay the
/// applied edit), render, read the frame back from `0xb8000`, then
/// unmount — the document goes back into [`DOC`] **with the completion
/// applied**, which the shell's `edit`/`ai apply` then see. Every error
/// string becomes a `FATAL: editor:` line.
fn prove_ai_edit(reply: &str) -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < AI_MIN_COLS || rows < AI_MIN_ROWS {
        return Err("text screen too small for the A5 frame (min 64x6)");
    }
    let mut ed = Editor::mount();

    // The insertion point is the seeded cursor's line; the seed line's
    // exact bytes are the baseline for every assertion below.
    let target = ed.buf.line_of(ed.cursor).ok_or("cursor lost its line")?;
    let seed_line = line_text(&ed.buf, target).ok_or("cursor line unreadable")?;
    let mut applied = seed_line.clone();
    applied.push_str(reply);

    // (a) Apply at the cursor — the A5 operation, one undo entry.
    if !insert_at(&mut ed.buf, &mut ed.cursor, reply) {
        return Err("completion insert refused");
    }
    if !line_equals(&ed.buf, target, applied.as_bytes()) {
        return Err("completion not applied at the cursor");
    }
    let applied_cursor = ed.cursor; // end of the just-applied completion

    // (b) Undo removes exactly the applied completion, redo restores it
    // byte-exact — driven on `editorbuf` directly (buffer level, before
    // any rendering), so the on-screen end state below can only be the
    // *restored* completion, never a lucky draw.
    if !ed.buf.undo() {
        return Err("undo of the applied completion returned false");
    }
    if !line_equals(&ed.buf, target, seed_line.as_bytes()) {
        return Err("undo did not remove the completion");
    }
    ed.clamp_cursor();
    if !ed.buf.redo() {
        return Err("redo of the applied completion returned false");
    }
    if !line_equals(&ed.buf, target, applied.as_bytes()) {
        return Err("redo did not restore the completion");
    }
    // Undo shrank the buffer from under the caret (A2's clamp rule can
    // leave it mid-text once redo brings the bytes back) — park it at
    // the end of the restored completion, where an editor leaves it
    // after an apply, and where the next `ai apply` appends.
    ed.cursor = applied_cursor;
    ed.clamp_cursor();

    // (c) The round-trip touched nothing else: the rest of the seed is
    // still byte-identical.
    if !line_starts_with(&ed.buf, 0, b"// reemplazo A5 - editor <-> AI") {
        return Err("undo trail corrupted the seed header");
    }
    if !line_starts_with(&ed.buf, 3, b"}") {
        return Err("undo trail corrupted the closing brace");
    }

    // (d) Render through the A1 path (ratatui → VgaBackend → screen
    // diff → `0xb8000`) and read back the visible end state: original
    // text and completion both on row 2, gutter and status intact.
    let mut terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
    terminal
        .draw(|frame| ed.render_into(frame))
        .map_err(|_| "A5 frame failed")?;

    let gutter = gutter_width(ed.buf.line_count());
    if !cells_hold(0, 0, gutter_cell(1, gutter).as_bytes()) {
        return Err("line-number gutter missing on row 0");
    }
    if !cells_hold(0, 2, gutter_cell(target + 1, gutter).as_bytes()) {
        return Err("line-number gutter missing on the edited row");
    }
    if !row_holds(target, b"let answer = 0; // TODO: ask AI") {
        return Err("original text missing from the screen");
    }
    if !row_holds(target, reply.as_bytes()) {
        return Err("applied completion missing from the screen");
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

    ed.unmount();
    Ok(())
}

/// Line `line` of `buf` as text, or `None` when it cannot be read.
/// (`editorbuf` guarantees UTF-8; the `Err` arm degrades to `None`
/// rather than panicking.)
fn line_text(buf: &Buffer, line: usize) -> Option<String> {
    let mut out = Vec::new();
    if !buf.line_bytes(line, &mut out) {
        return None;
    }
    String::from_utf8(out).ok()
}

/// Does line `line` of `buf` hold exactly `want`? (The A5 proof's
/// byte-exact assertions around the applied completion — `line_bytes`
/// excludes the trailing newline.)
fn line_equals(buf: &Buffer, line: usize, want: &[u8]) -> bool {
    let mut out = Vec::new();
    buf.line_bytes(line, &mut out) && out.as_slice() == want
}

// ---------------------------------------------------------------------------
// The `edit` builtin: interactive session
// ---------------------------------------------------------------------------

/// The `edit` shell builtin: open the **retained document** (the
/// in-memory sample on first use — module docs, A5) and edit it with the
/// polled keyboard until `Esc`, which saves the session back into the
/// document instead of dropping it. Fails soft — no text console or a
/// render error prints one line and returns to the prompt; when a frame
/// did reach the screen, the text buffer is cleared on exit so the shell
/// resumes on a clean screen (same contract as `tui`).
pub fn run() {
    if let Err(why) = screen::open() {
        serial_println!("editor: {why}");
        return;
    }
    // Mount before the session and unmount on *every* path out of it —
    // an early return must never lose the document.
    let mut ed = Editor::mount();
    let framed = session(&mut ed);
    ed.unmount();
    if framed {
        crate::vga::clear_screen();
    }
}

/// One interactive session on an already-mounted editor. Returns
/// whether any frame reached the screen (only then is the screen
/// cleared on exit).
fn session(ed: &mut Editor) -> bool {
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
