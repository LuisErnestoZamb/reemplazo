//! Milestone B2 (docs/browser.md §4 tree, §6 layout + rendering): the
//! text-mode browser view and the `BROWSER_RENDER_OK` boot proof.
//!
//! Three layers, all over the A1 screen layer (one rendering path for
//! every app — no fork):
//!
//! - **Tree**: [`dom::build`] (the host-tested arena builder) turns the
//!   fetch's bounded body sample into nodes. Every failure is
//!   fail-closed (`FATAL: browser:` + [`crate::halt`] via
//!   [`boot_proof`]).
//! - **Layout**: [`flatten`] walks the tree iteratively (explicit work
//!   stack — no recursion, depth already capped by `dom`) into a
//!   linear item stream, and [`LineBuilder`] turns that into positioned
//!   cells: block flow, greedy word wrap at the viewport width,
//!   headings by attribute (h1/h2 bold, h3–h6 dim+bold), list markers
//!   (`* ` bullet, `n. ` ordered, 2 cells of indent per nesting),
//!   `<pre>` whitespace preserved (newlines and double spaces, hard
//!   wrap), inline `<code>` dim, `<a>` **inverse** cells, `<br>` line
//!   breaks, `display:none` subtrees skipped (the one hardcoded CSS
//!   rule — the cascade is B3). Layout stops at [`LINE_CAP`] lines and
//!   at [`screen::dims`] bounds: a page that does not fit renders what
//!   fits, never panics.
//! - **Render**: [`render`] draws title bar (page `<title>`, cyan),
//!   the viewport (first `height-2` layout lines) and a status bar
//!   (sanitized URL, white-on-blue) through ratatui → `VgaBackend` →
//!   `screen::flush_diff` → `0xb8000`.
//!
//! **Glyph stance**: cells hold `char`s; text is UTF-8 (`dom` already
//! turned invalid bytes into `?`), U+00A0 is normalized to a plain
//! space at flatten time, and everything the CP437 font cannot draw
//! falls back to `?` in `screen::glyph` at draw time (the documented
//! docs/browser.md §6 rule — a full Unicode→CP437 table is later
//! polish). Serial output never carries page text: only the sanitized
//! URL and fixed strings reach `serial_println!`.
//!
//! # The proof (two frames, both read back from `0xb8000`)
//!
//! 1. **The fetched page** (`http://example.com` — see
//!    `browser::RENDER_URL`): title bar holds `Example Domain`, the
//!    paragraph fragment renders with the wrapped tail on a later row
//!    (word wrap proven), the status bar holds the sanitized URL, and
//!    the raw `<style>` content does **not** leak into the flow.
//! 2. **An embedded layout fixture** — because today's example.com
//!    carries no `<h1>`, no `<a>` and no list, the features B2 specs
//!    (heading attributes, bullet/ordered markers + nesting indent,
//!    `<pre>` whitespace, dim `<code>`, inverse link cells,
//!    `display:none` skip) are asserted on a fixture document the
//!    kernel owns. Zero extra network cost, deterministic assertions.

use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use dom::{Document, NodeKind};
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::Paragraph;
use ratatui::{Frame, Terminal};

/// Smallest text geometry the proof accepts: 50 columns keep the
/// example.com paragraph's asserted fragments unsplit, 16 rows hold
/// the whole fixture frame (title + 10 layout lines + status).
const MIN_COLS: usize = 50;
const MIN_ROWS: usize = 16;
/// Total layout lines per page (bounded memory: a hostile body cannot
/// grow the line list past this; the rest of the page is dropped).
const LINE_CAP: usize = 1024;
/// Title-bar attribute: cyan on black (`fg 6 | bg 0 << 4`).
const TITLE_ATTR: u8 = 0x06;
/// Status-bar attribute: white on blue (`fg 15 | bg 4 << 4`).
const STATUS_ATTR: u8 = 0x4F;
/// h1/h2 attribute: default fg + VGA bright bit (`fg 15`).
const HEADING_ATTR: u8 = 0x0F;
/// Inline `<code>` attribute: dark grey (`fg 8`).
const CODE_ATTR: u8 = 0x08;
/// `<a>` link attribute: default colors reversed (`fg 0 | bg 7 << 4`).
const LINK_ATTR: u8 = 0x70;
/// Title shown when the page carries no `<title>`.
const DEFAULT_TITLE: &str = "reemplazo browser";

/// Elements whose subtrees are never rendered: document head
/// plumbing, raw-text holders and templates. The tree keeps them
/// faithfully (`<style>` content is what B3's cascade will parse) —
/// layout just does not draw them.
const SKIP: [&str; 8] = [
    "head", "title", "meta", "link", "script", "style", "base", "template",
];

/// Block-level elements that force a line break but carry no marker
/// or style of their own (headings/`pre`/`li`/`p` have dedicated
/// arms). Tables degrade to plain flow: `tr` breaks the line, `td`
/// breaks it again — no grid in B2 (documented).
const BLOCK_LAYOUT: [&str; 26] = [
    "p",
    "div",
    "blockquote",
    "dl",
    "dt",
    "dd",
    "table",
    "tr",
    "td",
    "th",
    "section",
    "article",
    "aside",
    "header",
    "footer",
    "nav",
    "main",
    "figure",
    "figcaption",
    "address",
    "center",
    "fieldset",
    "form",
    "details",
    "summary",
    "hr",
];

/// The layout fixture — every B2 rendering feature on one document
/// (see the module docs for why the real page is not enough).
const FIXTURE: &str = "<title>layout fixture</title>\
                       <h1>Fixture heading</h1>\
                       <ul><li>first item<ul><li>nested item</li></ul></li></ul>\
                       <ol><li>ordered one</li></ol>\
                       <pre>pre  keeps  spaces\nsecond line</pre>\
                       <p>use <code>fn main</code> here</p>\
                       <p>See <a href=\"https://example.test/x\">the docs</a> for details.</p>\
                       <p style=\"display:none\">HIDDEN_MARKER</p>";

// ---------------------------------------------------------------------------
// Cell model + flatten (tree → linear items, iterative)
// ---------------------------------------------------------------------------

/// How one cell is styled (semantic — mapped to ratatui at draw time).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum S {
    /// Default text.
    Normal,
    /// Heading level 1–6 (1/2 bold-bright, 3–6 dim+bold).
    Heading(u8),
    /// `<b>`/`<strong>`.
    Bold,
    /// Inline `<code>` (dim).
    Code,
    /// Inside `<a>` — rendered inverse.
    Link,
}

/// One laid-out cell: a glyph and its semantic style.
#[derive(Clone, Copy)]
struct Cell {
    ch: char,
    s: S,
}

/// A block boundary handed to the line builder.
enum Blk {
    /// Paragraph (blank line before when the previous line has ink).
    Para {
        /// Left indent in cells (list depth × 2).
        indent: usize,
    },
    /// Heading: flush + blank-before + bold style on following text.
    Heading {
        /// Left indent in cells.
        indent: usize,
    },
    /// `<pre>`: whitespace-preserving mode until the next block.
    Pre {
        /// Left indent in cells.
        indent: usize,
    },
    /// Generic block: flush only.
    Div {
        /// Left indent in cells.
        indent: usize,
    },
    /// List item: marker placed at the line start, indent for the
    /// item's first line (continuation lines keep the indent, not the
    /// marker).
    ListItem {
        /// Marker text (`"* "` or `"1. "`).
        marker: String,
        /// Left indent in cells.
        indent: usize,
    },
}

/// One linear item of the flow.
enum Item {
    /// Block boundary.
    Block(Blk),
    /// A text run with the style in effect where it appeared.
    Text(String, S),
    /// `<br>` — forced line break.
    Break,
}

/// Work-stack command for the iterative tree walk.
enum Cmd {
    /// Visit a node (document order).
    Visit(usize),
    /// Restore the style/list context saved when entering an element.
    Leave(S, usize),
}

/// Depth of `name` as a heading (`h1`–`h6`), or `None`.
fn heading_level(name: &str) -> Option<u8> {
    match name.as_bytes() {
        [b'h', d] if (b'1'..=b'6').contains(d) => Some(*d - b'0'),
        _ => None,
    }
}

/// The one hardcoded CSS rule of B2: an inline `style` whose
/// whitespace-stripped, lowercased text says `display:none` hides the
/// subtree. The cascade proper is milestone B3.
fn display_none(e: &dom::Element) -> bool {
    let Some(style) = e.attr("style") else {
        return false;
    };
    let mut norm = String::with_capacity(style.len());
    for c in style.chars() {
        if c != ' ' && c != '\t' {
            norm.push(c.to_ascii_lowercase());
        }
    }
    norm.contains("display:none")
}

/// Text-node copy for the item stream: U+00A0 (from `&nbsp;`) becomes
/// a plain space so word wrap treats it as the separator it is; every
/// other char passes through (glyph fallback happens at draw time).
fn flatten_text(t: &str) -> String {
    if t.contains('\u{00A0}') {
        t.replace('\u{00A0}', " ")
    } else {
        t.to_string()
    }
}

/// Push a node's children onto the work stack in reverse, so `pop`
/// yields document order (iterative preorder — never recursive).
fn push_kids(doc: &Document, node: &dom::Node, work: &mut Vec<Cmd>) {
    let mut kids = Vec::new();
    let mut cur = node.first_child;
    while let Some(cid) = cur {
        kids.push(cid);
        cur = doc.node(cid).and_then(|n| n.next_sibling);
    }
    for kid in kids.into_iter().rev() {
        work.push(Cmd::Visit(kid));
    }
}

/// Walk the tree into a linear item stream: styles and list context
/// are saved/restored through `Leave` commands, skipped subtrees never
/// enter the stream. Heap-only state, bounded by `dom`'s caps.
fn flatten(doc: &Document) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut work: Vec<Cmd> = Vec::new();
    work.push(Cmd::Visit(doc.root()));
    let mut style = S::Normal;
    // (ordered?, item count) per open `ul`/`ol`.
    let mut lists: Vec<(bool, usize)> = Vec::new();
    while let Some(cmd) = work.pop() {
        match cmd {
            Cmd::Leave(saved_style, saved_lists) => {
                style = saved_style;
                lists.truncate(saved_lists);
            }
            Cmd::Visit(id) => {
                let Some(node) = doc.node(id) else {
                    continue; // invariant slip: fail-closed, skip
                };
                match &node.kind {
                    NodeKind::Document => push_kids(doc, node, &mut work),
                    NodeKind::Text(t) => items.push(Item::Text(flatten_text(t), style)),
                    NodeKind::Element(e) => {
                        if SKIP.contains(&e.name.as_str()) || display_none(e) {
                            continue;
                        }
                        // Save the context *before* this element's
                        // effects — `Leave` restores it exactly.
                        work.push(Cmd::Leave(style, lists.len()));
                        match e.name.as_str() {
                            "ul" => lists.push((false, 0)),
                            "ol" => lists.push((true, 0)),
                            "li" => {
                                let depth = lists.len();
                                let (ordered, count) = match lists.last_mut() {
                                    Some(l) => {
                                        l.1 = l.1.saturating_add(1);
                                        (l.0, l.1)
                                    }
                                    None => (false, 0),
                                };
                                let marker = if ordered {
                                    format!("{count}. ")
                                } else {
                                    String::from("* ")
                                };
                                // First-level items sit at 0, nested
                                // ones indent two cells per level.
                                let indent = depth.saturating_sub(1).saturating_mul(2);
                                items.push(Item::Block(Blk::ListItem { marker, indent }));
                            }
                            "pre" => items.push(Item::Block(Blk::Pre {
                                indent: lists.len().saturating_mul(2),
                            })),
                            "code" => style = S::Code,
                            "a" => style = S::Link,
                            "br" => items.push(Item::Break),
                            "b" | "strong" => style = S::Bold,
                            "p" => items.push(Item::Block(Blk::Para {
                                indent: lists.len().saturating_mul(2),
                            })),
                            name => {
                                if let Some(level) = heading_level(name) {
                                    items.push(Item::Block(Blk::Heading {
                                        indent: lists.len().saturating_mul(2),
                                    }));
                                    style = S::Heading(level);
                                } else if BLOCK_LAYOUT.contains(&name) {
                                    items.push(Item::Block(Blk::Div {
                                        indent: lists.len().saturating_mul(2),
                                    }));
                                }
                            }
                        }
                        push_kids(doc, node, &mut work);
                    }
                }
            }
        }
    }
    items
}

// ---------------------------------------------------------------------------
// Line building: block flow + word wrap at the viewport width
// ---------------------------------------------------------------------------

/// Split `s` at the `n`-th char (both parts on char boundaries).
/// `n == 0` → `("", s)`; `n ≥ len` → `(s, "")`.
fn split_at_chars(s: &str, n: usize) -> (&str, &str) {
    for (taken, (i, _)) in s.char_indices().enumerate() {
        if taken == n {
            return s.split_at(i);
        }
    }
    (s, "")
}

/// Greedy line builder. Every buffer it touches is bounded: a line
/// never exceeds `width` cells, the line list never exceeds `cap`.
struct LineBuilder {
    lines: Vec<Vec<Cell>>,
    cur: Vec<Cell>,
    width: usize,
    cap: usize,
    full: bool,
    indent: usize,
    pending_marker: Option<String>,
    /// Cells before this offset are prefix (indent + marker); content
    /// starts here.
    line_start: usize,
    line_started: bool,
    pre: bool,
    pending_space: bool,
}

impl LineBuilder {
    fn new(width: usize, cap: usize) -> Self {
        LineBuilder {
            lines: Vec::new(),
            cur: Vec::new(),
            // width ≥ 1 keeps the hard-break loop's progress proof
            // (the proof's MIN_COLS is far above this floor).
            width: width.max(1),
            cap,
            full: false,
            indent: 0,
            pending_marker: None,
            line_start: 0,
            line_started: false,
            pre: false,
            pending_space: false,
        }
    }

    /// True once real content (beyond indent/marker) sits on the line.
    fn has_content(&self) -> bool {
        self.line_started && self.cur.len() > self.line_start
    }

    /// Start the current line: indent prefix, then the pending list
    /// marker (first line of an item only).
    fn ensure_line(&mut self) {
        if self.line_started {
            return;
        }
        self.line_started = true;
        self.line_start = 0;
        let indent = self.indent.min(self.width.saturating_sub(1));
        for _ in 0..indent {
            self.cur.push(Cell {
                ch: ' ',
                s: S::Normal,
            });
            self.line_start += 1;
        }
        if let Some(marker) = self.pending_marker.take() {
            for ch in marker.chars() {
                if self.cur.len() >= self.width {
                    break;
                }
                self.cur.push(Cell { ch, s: S::Normal });
                self.line_start += 1;
            }
        }
    }

    /// End the current line (no-op when nothing was started — so
    /// block boundaries never invent blank lines on their own).
    fn flush(&mut self) {
        if !self.line_started {
            return;
        }
        self.line_started = false;
        self.pending_space = false;
        if self.full {
            self.cur.clear();
            return;
        }
        if self.lines.len() >= self.cap {
            self.full = true;
            self.cur.clear();
            return;
        }
        self.lines.push(core::mem::take(&mut self.cur));
    }

    /// Push an explicitly blank line (paragraph/heading separation).
    fn blank(&mut self) {
        if self.full {
            return;
        }
        if self.lines.len() >= self.cap {
            self.full = true;
            return;
        }
        self.lines.push(Vec::new());
    }

    fn block(&mut self, b: Blk) {
        self.flush();
        match b {
            Blk::Para { indent } | Blk::Heading { indent } => {
                // Separate consecutive blocks with one blank line, but
                // never start the document with one.
                if matches!(self.lines.last(), Some(l) if !l.is_empty()) {
                    self.blank();
                }
                self.indent = indent;
                self.pre = false;
                self.pending_marker = None;
            }
            Blk::Pre { indent } => {
                self.indent = indent;
                self.pre = true;
                self.pending_marker = None;
            }
            Blk::Div { indent } => {
                self.indent = indent;
                self.pre = false;
                self.pending_marker = None;
            }
            Blk::ListItem { marker, indent } => {
                self.indent = indent;
                self.pre = false;
                self.pending_marker = Some(marker);
                // The marker line exists even for an empty item.
                self.ensure_line();
            }
        }
        self.pending_space = false;
    }

    fn br(&mut self) {
        self.flush();
    }

    fn text(&mut self, s: &str, style: S) {
        if s.is_empty() {
            return;
        }
        if self.pre {
            self.text_pre(s, style);
            return;
        }
        // Whitespace at a run's edges sets (or clears) the pending
        // space that the next word consumes — this is what keeps
        // `<b>foo</b>bar` glued and `<b>foo</b> <i>bar</i>` spaced.
        if s.starts_with(char::is_whitespace) && self.has_content() {
            self.pending_space = true;
        }
        for word in s.split(char::is_whitespace) {
            if word.is_empty() {
                continue;
            }
            self.put_word(word, style);
            self.pending_space = true;
        }
        // Trailing whitespace keeps the pending space for the next
        // run (only when there is already content to separate from);
        // no trailing whitespace means the next run continues the
        // current word directly (`<b>foo</b>bar` stays glued).
        self.pending_space = if s.ends_with(char::is_whitespace) {
            self.has_content()
        } else {
            false
        };
    }

    /// Greedy wrap: fit the word (and its pending space); otherwise
    /// end the line and hard-break a word that cannot fit a whole one.
    fn put_word(&mut self, word: &str, style: S) {
        self.ensure_line();
        let wlen = word.chars().count();
        let space = usize::from(self.pending_space && self.has_content());
        let avail = self
            .width
            .saturating_sub(self.cur.len())
            .saturating_sub(space);
        if wlen <= avail {
            if space == 1 {
                self.cur.push(Cell { ch: ' ', s: style });
            }
            for ch in word.chars() {
                self.cur.push(Cell { ch, s: style });
            }
            return;
        }
        // Wrap to a fresh line (a marker-only line is kept as-is).
        if self.line_started {
            self.flush();
        }
        self.ensure_line();
        let mut rest = word;
        loop {
            let avail = self.width.saturating_sub(self.cur.len());
            if avail == 0 {
                self.flush();
                self.ensure_line();
                continue;
            }
            let take_n = avail.min(rest.chars().count());
            let (head, tail) = split_at_chars(rest, take_n);
            for ch in head.chars() {
                self.cur.push(Cell { ch, s: style });
            }
            rest = tail;
            if rest.is_empty() {
                break;
            }
            self.flush();
            self.ensure_line();
        }
    }

    /// `<pre>` text: newlines are line breaks, spaces are kept, long
    /// lines hard-wrap at the width.
    fn text_pre(&mut self, s: &str, style: S) {
        for ch in s.chars() {
            if ch == '\n' {
                self.ensure_line();
                self.flush();
                continue;
            }
            self.ensure_line();
            if self.cur.len() >= self.width {
                self.flush();
                self.ensure_line();
            }
            self.cur.push(Cell { ch, s: style });
        }
    }

    fn finish(mut self) -> Vec<Vec<Cell>> {
        self.flush();
        self.lines
    }
}

/// Flatten + line-build: the whole layout pipeline, iterative and
/// bounded on both ends.
fn layout(doc: &Document, width: usize, cap: usize) -> Vec<Vec<Cell>> {
    let items = flatten(doc);
    let mut builder = LineBuilder::new(width, cap);
    for item in items {
        match item {
            Item::Block(b) => builder.block(b),
            Item::Text(t, s) => builder.text(&t, s),
            Item::Break => builder.br(),
        }
    }
    builder.finish()
}

// ---------------------------------------------------------------------------
// Rendering through the A1 screen layer
// ---------------------------------------------------------------------------

/// Semantic style → ratatui (the two VGA-expressible modifiers plus
/// colors; `VgaBackend::colors` turns BOLD into the bright bit and
/// REVERSED into swapped indices).
fn rs(s: S) -> Style {
    match s {
        S::Normal => Style::new(),
        S::Heading(1) | S::Heading(2) => Style::new().add_modifier(Modifier::BOLD),
        S::Heading(_) => Style::new()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::BOLD),
        S::Bold => Style::new().add_modifier(Modifier::BOLD),
        S::Code => Style::new().fg(Color::DarkGray),
        S::Link => Style::new().add_modifier(Modifier::REVERSED),
    }
}

/// Layout cells → ratatui lines, merging runs of equal style into one
/// span each (bounded: ≤ width cells per line, ≤ viewport lines).
fn ratatui_lines(lines: &[Vec<Cell>], width: usize, max: usize) -> Vec<Line<'static>> {
    lines
        .iter()
        .take(max)
        .map(|cells| {
            let mut spans: Vec<Span<'static>> = Vec::new();
            let mut run = String::new();
            let mut run_style: Option<S> = None;
            for cell in cells.iter().take(width) {
                if run_style != Some(cell.s) {
                    if let Some(prev) = run_style.take() {
                        spans.push(Span::styled(core::mem::take(&mut run), rs(prev)));
                    }
                    run_style = Some(cell.s);
                }
                run.push(cell.ch);
            }
            if !run.is_empty() {
                spans.push(Span::styled(run, rs(run_style.unwrap_or(S::Normal))));
            }
            Line::from(spans)
        })
        .collect()
}

/// One frame: title bar (row 0), viewport (the first `height-2`
/// layout lines), status bar (last row). Degenerate geometry draws
/// nothing instead of panicking.
fn render(frame: &mut Frame, title: &str, status: &str, lines: &[Vec<Cell>]) {
    let area = frame.area();
    let Some(status_off) = usize::from(area.height).checked_sub(1) else {
        return;
    };
    if status_off == 0 {
        return;
    }
    let Some(page_h) = status_off.checked_sub(1) else {
        return;
    };
    let title_area = Rect::new(area.x, area.y, area.width, 1);
    let page_area = Rect::new(
        area.x,
        area.y.saturating_add(1),
        area.width,
        page_h as u16, // page_h < area.height ≤ u16::MAX
    );
    let status_area = Rect::new(
        area.x,
        area.y.saturating_add(status_off as u16),
        area.width,
        1,
    );
    frame.render_widget(
        Paragraph::new(title).style(Style::new().fg(Color::Cyan)),
        title_area,
    );
    let page = Text::from(ratatui_lines(lines, usize::from(area.width), page_h));
    frame.render_widget(Paragraph::new(page), page_area);
    frame.render_widget(
        Paragraph::new(status).style(Style::new().fg(Color::White).bg(Color::Blue)),
        status_area,
    );
}

/// Title bar text from wire data: printable ASCII only, truncated to
/// the viewport width (the same `?`-for-everything-else policy as
/// `browser::sanitize`, applied per char).
fn sanitize_display(s: &str, max: usize) -> String {
    let mut out = String::new();
    for c in s.chars().take(max) {
        out.push(if c.is_ascii_graphic() || c == ' ' {
            c
        } else {
            '?'
        });
    }
    out
}

/// Build → layout → draw one page into the viewport. The staged
/// screen buffer is cleared first, so `flush_diff` overwrites every
/// cell of the previous frame (or of the mirrored serial log).
fn draw_page(html: &[u8], status: &str, cols: usize) -> Result<(), &'static str> {
    let doc = dom::build(html).map_err(|e| e.as_str())?;
    let lines = layout(&doc, cols, LINE_CAP);
    let title = sanitize_display(doc.title().as_deref().unwrap_or(DEFAULT_TITLE), cols);
    screen::clear();
    let mut terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
    terminal
        .draw(|frame| render(frame, &title, status, &lines))
        .map_err(|_| "browser frame failed")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The boot proof: BROWSER_RENDER_OK
// ---------------------------------------------------------------------------

/// Fetch → tree → layout → render → read back from `0xb8000`, twice
/// (the fetched page, then the feature fixture) — the smoke test's
/// `BROWSER_RENDER_OK`, printed between `AI_EDIT_OK` and `SHELL_OK`.
/// On any mismatch: `FATAL: browser:` + [`crate::halt`], like every
/// other boot proof; a genuinely absent text console skips the proof
/// (the `TUI_OK` rule). Afterwards the screen is cleared and the
/// console cursor reset, so the shell starts clean — serial output is
/// never reordered or suppressed. `html` is the fetch's bounded body
/// sample and `status` the already-sanitized final URL.
pub fn boot_proof(html: &[u8], status: &str) {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: browser: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove(html, status) {
        serial_println!("FATAL: browser: {why}");
        crate::halt();
    }
    serial_println!("BROWSER_RENDER_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// Both frames plus every readback assertion. Fail-closed: each error
/// string becomes a `FATAL: browser:` line.
fn prove(html: &[u8], status: &str) -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the browser frame (min 50x16)");
    }
    let status_row = rows.checked_sub(1).ok_or("no status row")?;

    // Frame 1 — the fetched page (real wire content).
    draw_page(html, status, cols)?;
    if !row_holds(0, b"Example Domain") {
        return Err("page title missing from the title bar");
    }
    if !row_holds_attr(0, TITLE_ATTR) {
        return Err("title bar attribute missing");
    }
    if !screen_anywhere(b"documentation examples") {
        return Err("paragraph text missing from the viewport");
    }
    if !screen_anywhere(b"monitoring purposes") {
        return Err("wrapped paragraph tail missing (word wrap)");
    }
    if screen_anywhere(b"color-scheme") {
        return Err("raw <style> content leaked into the render");
    }
    // The status bar shows the final URL — printable ASCII by
    // `browser::sanitize`, clipped to the viewport width.
    let show = status.as_bytes().get(..cols).unwrap_or(status.as_bytes());
    if !row_holds(status_row, show) {
        return Err("status bar URL missing");
    }
    if !row_holds_attr(status_row, STATUS_ATTR) {
        return Err("status bar attribute missing");
    }

    // Frame 2 — the layout fixture (features today's example.com
    // does not carry: heading, lists, pre, code, link, display:none).
    draw_page(FIXTURE.as_bytes(), "layout fixture", cols)?;
    if !row_holds(0, b"layout fixture") {
        return Err("fixture title missing from the title bar");
    }
    let Some(y) = row_with(b"Fixture heading") else {
        return Err("fixture heading missing from the viewport");
    };
    if !row_holds_attr(y, HEADING_ATTR) {
        return Err("heading attribute missing (bold)");
    }
    if !screen_anywhere(b"* first item") {
        return Err("bullet list marker missing");
    }
    if !screen_anywhere(b"  * nested item") {
        return Err("nested list indent missing");
    }
    if !screen_anywhere(b"1. ordered one") {
        return Err("ordered list marker missing");
    }
    if !screen_anywhere(b"pre  keeps  spaces") {
        return Err("pre whitespace not preserved");
    }
    if !screen_anywhere(b"second line") {
        return Err("pre line break missing");
    }
    let Some(y) = row_with(b"fn main") else {
        return Err("inline code missing from the viewport");
    };
    if !row_holds_attr(y, CODE_ATTR) {
        return Err("code attribute missing (dim)");
    }
    let Some(y) = row_with(b"the docs") else {
        return Err("link text missing from the viewport");
    };
    if !row_holds_attr(y, LINK_ATTR) {
        return Err("link cells not rendered inverse");
    }
    if screen_anywhere(b"HIDDEN_MARKER") {
        return Err("display:none subtree was rendered");
    }
    Ok(())
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

/// The first row of the *actual* text buffer holding `needle`.
fn row_with(needle: &[u8]) -> Option<usize> {
    let (_, rows) = screen::dims()?;
    (0..rows).find(|&y| row_holds(y, needle))
}

/// Does any row hold `needle`?
fn screen_anywhere(needle: &[u8]) -> bool {
    row_with(needle).is_some()
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
