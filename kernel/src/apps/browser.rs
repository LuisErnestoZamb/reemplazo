//! Milestones B2 + B3 (docs/browser.md §4 tree, §5 CSS, §6 layout and
//! rendering): the text-mode browser view, its `BROWSER_RENDER_OK` and
//! `BROWSER_CSS_OK` boot proofs.
//!
//! Three layers, all over the A1 screen layer (one rendering path for
//! every app — no fork):
//!
//! - **Tree**: [`dom::build`] (the host-tested arena builder) turns the
//!   fetch's bounded body sample into nodes. Every failure is
//!   fail-closed (`FATAL: browser:` + [`crate::halt`] via
//!   [`boot_proof`]).
//! - **Style** (B3): every `<style>` subtree's text (stored verbatim by
//!   `dom`) is concatenated and parsed **once per render** by
//!   `csscore`; inline `style=""` attributes go through the same
//!   declaration parser. [`flatten`] cascades per element and applies
//!   the result: `display:none` skips the subtree, colors become VGA
//!   attribute indices, `font-weight` the bright bit, `font-style` the
//!   dim half, left margins/paddings a block indent, `width` the block's
//!   wrap width, `list-style-type` the item marker. Inheritance follows
//!   CSS for color/font/decoration and — documented divergence — for
//!   `background-color` (the layout paints glyph cells only, no boxes).
//!   With no applicable CSS every element's [`Computed`] is default and
//!   the render is **byte-identical** to B2 (its proofs are the
//!   regression net).
//! - **Layout**: [`flatten`] walks the tree iteratively (explicit work
//!   stack — no recursion, depth already capped by `dom`) into a
//!   linear item stream, and [`LineBuilder`] turns that into positioned
//!   cells: block flow, greedy word wrap at the viewport width,
//!   headings by attribute (h1/h2 bold, h3–h6 dim+bold), list markers
//!   (`* ` bullet, `n. ` ordered, 2 cells of indent per nesting),
//!   `<pre>` whitespace preserved (newlines and double spaces, hard
//!   wrap), inline `<code>` dim, `<a>` **inverse** cells, `<br>` line
//!   breaks. Layout stops at [`LINE_CAP`] lines and at [`screen::dims`]
//!   bounds: a page that does not fit renders what fits, never panics.
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
//! # The proofs (both read back from `0xb8000`)
//!
//! 1. **The fetched page** (`http://example.com` — see
//!    `browser::RENDER_URL`): title bar holds `Example Domain`, the
//!    paragraph fragment renders with the wrapped tail on a later row
//!    (word wrap proven), the status bar holds the sanitized URL, and
//!    the raw `<style>` content does **not** leak into the flow. Its
//!    CSS declares only properties outside the B3 subset (documented
//!    in docs/browser.md §5), so this frame is the unstyled
//!    regression net.
//! 2. **An embedded layout fixture** — because today's example.com
//!    carries no `<h1>`, no `<a>` and no list, the features B2 specs
//!    (heading attributes, bullet/ordered markers + nesting indent,
//!    `<pre>` whitespace, dim `<code>`, inverse link cells,
//!    `display:none` skip) are asserted on a fixture document the
//!    kernel owns. Zero extra network cost, deterministic assertions.
//! 3. **A styled/unstyled CSS pair** (B3, [`css_boot_proof`]): the same
//!    fixture body rendered with and without a stylesheet, asserting
//!    the exact VGA attribute bytes (colors, background, bold), the
//!    margin/padding cell shift, `display:none` absence and — on the
//!    unstyled twin — the default attributes, so "CSS changed the
//!    frame" is machine-checked, not eyeballed. Then the real page is
//!    rendered once more with its own sheet applied (robustness pass;
//!    nothing is asserted about wire CSS).

use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use csscore::{Display, FontStyle, FontWeight, ListStyle, Stylesheet, Tree as CssTree};
use dom::{Document, NodeKind};
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
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
/// Bytes of concatenated `<style>` text parsed per render (defense in
/// depth: the fetch's body sample is already ≤ `BROWSER_SAMPLE`, and
/// `csscore` clamps its own input at `csscore::INPUT_CAP`).
const STYLE_CAP: usize = 32 * 1024;
/// Maximum blank lines one element's top margin/padding may add (a
/// hostile `margin-top: 65535` cannot scroll the page away).
const BLOCK_SPACE_CAP: usize = 4;
/// Maximum nesting of width overrides (shadowed by `dom::DEPTH_CAP`,
/// but the builder keeps its own bound).
const WIDTH_STACK_CAP: usize = 64;
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

/// The HTML-derived base of a cell (what B2's hardcoded semantics
/// were).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
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

/// How one cell is styled: the HTML base plus the CSS overlay inherited
/// into it (B3). With no overlay this resolves to exactly the B2
/// attributes (see [`rs`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct S {
    base: Base,
    /// Explicit foreground VGA index from `color`.
    fg: Option<u8>,
    /// Explicit background VGA index from `background-color`.
    bg: Option<u8>,
    /// `font-weight` when specified (`None` = the base decides).
    bold: Option<bool>,
    /// `font-style: italic` (rendered as the dim half — VGA has no
    /// italics).
    dim: bool,
}

impl S {
    const fn normal() -> Self {
        S {
            base: Base::Normal,
            fg: None,
            bg: None,
            bold: None,
            dim: false,
        }
    }

    const fn with_fg(mut self, fg: u8) -> Self {
        self.fg = Some(fg);
        self
    }

    const fn with_bg(mut self, bg: u8) -> Self {
        self.bg = Some(bg);
        self
    }

    const fn with_bold(mut self, bold: bool) -> Self {
        self.bold = Some(bold);
        self
    }

    const fn with_dim(mut self, dim: bool) -> Self {
        self.dim = dim;
        self
    }
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
        /// Left indent in cells (lists, margins, padding).
        indent: usize,
        /// Extra blank lines before the block (top margin/padding).
        before: usize,
    },
    /// Heading: flush + blank-before + bold style on following text.
    Heading {
        /// Left indent in cells.
        indent: usize,
        /// Extra blank lines before the block.
        before: usize,
    },
    /// `<pre>`: whitespace-preserving mode until the next block.
    Pre {
        /// Left indent in cells.
        indent: usize,
        /// Extra blank lines before the block.
        before: usize,
    },
    /// Generic block: flush only.
    Div {
        /// Left indent in cells.
        indent: usize,
        /// Extra blank lines before the block.
        before: usize,
    },
    /// List item: marker placed at the line start, indent for the
    /// item's first line (continuation lines keep the indent, not the
    /// marker). `marker: None` is `list-style-type: none`.
    ListItem {
        /// Marker text (`"* "`, `"- "` or `"1. "`); `None` = no marker.
        marker: Option<String>,
        /// Left indent in cells.
        indent: usize,
        /// Extra blank lines before the block.
        before: usize,
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
    /// Narrow the wrap width for the following block's content (CSS
    /// `width`, in cells; depth-capped by [`WIDTH_STACK_CAP`]).
    PushWidth(usize),
    /// Restore the enclosing wrap width.
    PopWidth,
}

/// Work-stack command for the iterative tree walk.
enum Cmd {
    /// Visit a node (document order).
    Visit(usize),
    /// Restore the style/list context saved when entering an element,
    /// and emit [`Item::PopWidth`] when that element pushed a width.
    Leave {
        /// Cell style in effect outside the element.
        style: S,
        /// `lists` stack depth outside the element.
        lists: usize,
        /// Whether the element pushed a CSS width (→ pop on leave).
        pop_width: bool,
    },
}

/// Depth of `name` as a heading (`h1`–`h6`), or `None`.
fn heading_level(name: &str) -> Option<u8> {
    match name.as_bytes() {
        [b'h', d] if (b'1'..=b'6').contains(d) => Some(*d - b'0'),
        _ => None,
    }
}

// The one hardcoded CSS rule of B2 (`display:none` from an inline
// `style`) is gone in B3: `csscore` parses the inline attribute through
// the same declaration parser as the sheet, so the cascade handles it
// with the same fail-soft rules.

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

/// The `dom` arena seen through `csscore`'s selector-matching trait
/// (zero dependencies in `csscore` — the adapter lives here).
struct Page<'a> {
    doc: &'a Document,
}

impl CssTree for Page<'_> {
    fn parent_element(&self, node: usize) -> Option<usize> {
        let parent = self.doc.node(node)?.parent?;
        match self.doc.node(parent)?.kind {
            NodeKind::Element(_) => Some(parent),
            // The only non-element parent is the document root.
            _ => None,
        }
    }

    fn element(&self, node: usize) -> Option<csscore::ElementRef<'_>> {
        let node = self.doc.node(node)?;
        match &node.kind {
            NodeKind::Element(e) => Some(csscore::ElementRef {
                name: &e.name,
                id: e.attr("id"),
                class: e.attr("class"),
                style: e.attr("style"),
            }),
            _ => None,
        }
    }
}

/// Concatenate every `<style>` subtree's text (stored verbatim by
/// `dom` — no entity decoding, per the HTML raw-text rules), bounded by
/// [`STYLE_CAP`]. `<link rel=stylesheet>` is out of B3's scope
/// (docs/browser.md §5): only embedded sheets are read.
fn collect_styles(doc: &Document) -> String {
    let mut out = String::new();
    let mut work: Vec<usize> = alloc::vec![doc.root()];
    while let Some(id) = work.pop() {
        let Some(node) = doc.node(id) else {
            break; // invariant slip: fail-closed, nothing more to read
        };
        if let NodeKind::Element(e) = &node.kind
            && e.name == "style"
        {
            let mut cur = node.first_child;
            while let Some(child_id) = cur {
                if let Some(child) = doc.node(child_id)
                    && let NodeKind::Text(text) = &child.kind
                    && out.len().saturating_add(text.len()) <= STYLE_CAP
                {
                    out.push_str(text);
                }
                cur = doc.node(child_id).and_then(|n| n.next_sibling);
            }
            continue; // `<style>` content is never a layout subtree
        }
        // Push children (reversed, so `pop` yields document order).
        let mut kids = Vec::new();
        let mut cur = node.first_child;
        while let Some(child_id) = cur {
            kids.push(child_id);
            cur = doc.node(child_id).and_then(|n| n.next_sibling);
        }
        for kid in kids.into_iter().rev() {
            work.push(kid);
        }
    }
    out
}

/// Walk the tree into a linear item stream: styles (HTML base + the
/// B3 cascade overlay) and list context are saved/restored through
/// `Leave` commands, skipped subtrees never enter the stream. Heap-only
/// state, bounded by `dom`'s caps.
fn flatten(doc: &Document, sheet: &Stylesheet, width: usize) -> Vec<Item> {
    let mut items: Vec<Item> = Vec::new();
    let mut work: Vec<Cmd> = Vec::new();
    work.push(Cmd::Visit(doc.root()));
    let page = Page { doc };
    let mut style = S::normal();
    // (ordered?, item count, list-style from the ul/ol) per open list.
    let mut lists: Vec<(bool, usize, Option<ListStyle>)> = Vec::new();
    while let Some(cmd) = work.pop() {
        match cmd {
            Cmd::Leave {
                style: saved,
                lists: saved_lists,
                pop_width,
            } => {
                style = saved;
                lists.truncate(saved_lists);
                if pop_width {
                    items.push(Item::PopWidth);
                }
            }
            Cmd::Visit(id) => {
                let Some(node) = doc.node(id) else {
                    continue; // invariant slip: fail-closed, skip
                };
                match &node.kind {
                    NodeKind::Document => push_kids(doc, node, &mut work),
                    NodeKind::Text(t) => items.push(Item::Text(flatten_text(t), style)),
                    NodeKind::Element(e) => {
                        if SKIP.contains(&e.name.as_str()) {
                            continue;
                        }
                        let computed = csscore::compute(&page, id, sheet);
                        if matches!(computed.display, Some(Display::None)) {
                            continue;
                        }
                        // Inheritance: start from the parent's cell
                        // style, then apply this element's specified
                        // values (color/font/decoration inherit in CSS;
                        // `background-color` too — documented divergence,
                        // the layout paints no block boxes).
                        let mut child = style;
                        if let Some(fg) = computed.color {
                            child = child.with_fg(fg);
                        }
                        if let Some(bg) = computed.background {
                            child = child.with_bg(bg);
                        }
                        if let Some(weight) = computed.font_weight {
                            child = child.with_bold(weight == FontWeight::Bold);
                        }
                        if let Some(face) = computed.font_style {
                            child = child.with_dim(face == FontStyle::Italic);
                        }
                        // `text-decoration` is parsed; VGA text cells
                        // have no underline bit (documented no-op).

                        let list_indent = lists.len().saturating_mul(2);
                        let box_indent = usize::from(computed.margin.left)
                            .saturating_add(usize::from(computed.padding.left));
                        let indent = list_indent.saturating_add(box_indent);
                        let before = usize::from(computed.margin.top)
                            .saturating_add(usize::from(computed.padding.top));

                        let forced_block = matches!(computed.display, Some(Display::Block));
                        let forced_inline = matches!(computed.display, Some(Display::Inline));
                        let named_block = BLOCK_LAYOUT.contains(&e.name.as_str())
                            || heading_level(&e.name).is_some()
                            || e.name == "pre"
                            || e.name == "li";
                        let blocky = !forced_inline && (forced_block || named_block);

                        // CSS `width` narrows the wrap width of a block's
                        // content (inline widths have no box to apply to).
                        // The percentage basis is the viewport width the
                        // caller laid this page out for.
                        let width_pushed = if blocky {
                            computed.width.and_then(|length| {
                                let cells = length.to_cells(width);
                                (cells >= 1).then_some(cells)
                            })
                        } else {
                            None
                        };
                        work.push(Cmd::Leave {
                            style,
                            lists: lists.len(),
                            pop_width: width_pushed.is_some(),
                        });

                        let mut pushed_block = false;
                        match e.name.as_str() {
                            "ul" => lists.push((false, 0, computed.list_style)),
                            "ol" => lists.push((true, 0, computed.list_style)),
                            "li" => {
                                let (ordered, count, frame_style) = match lists.last_mut() {
                                    Some(list) => {
                                        list.1 = list.1.saturating_add(1);
                                        (list.0, list.1, list.2)
                                    }
                                    None => (false, 0, None),
                                };
                                let marker_style = computed.list_style.or(frame_style);
                                let marker = match marker_style {
                                    Some(ListStyle::None) => None,
                                    Some(ListStyle::Dash) => Some(String::from("- ")),
                                    _ if ordered => Some(format!("{count}. ")),
                                    _ => Some(String::from("* ")),
                                };
                                if blocky {
                                    items.push(Item::Block(Blk::ListItem {
                                        marker,
                                        indent,
                                        before,
                                    }));
                                    pushed_block = true;
                                }
                            }
                            "pre" => {
                                if blocky {
                                    items.push(Item::Block(Blk::Pre { indent, before }));
                                    pushed_block = true;
                                }
                            }
                            "code" => child.base = Base::Code,
                            "a" => child.base = Base::Link,
                            "br" => items.push(Item::Break),
                            "b" | "strong" => child.base = Base::Bold,
                            "p" => {
                                if blocky {
                                    items.push(Item::Block(Blk::Para { indent, before }));
                                    pushed_block = true;
                                }
                            }
                            name => {
                                if let Some(level) = heading_level(name) {
                                    child.base = Base::Heading(level);
                                    if blocky {
                                        items.push(Item::Block(Blk::Heading { indent, before }));
                                        pushed_block = true;
                                    }
                                }
                            }
                        }
                        if let Some(cells) = width_pushed {
                            items.push(Item::PushWidth(cells));
                        }
                        // `display:block` on an element the HTML never
                        // breaks (span, section, …) still gets a block.
                        if blocky && !pushed_block {
                            items.push(Item::Block(Blk::Div { indent, before }));
                        }
                        style = child;
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
/// never exceeds the current width, the line list never exceeds
/// `cap`, and the width-override stack is capped at
/// [`WIDTH_STACK_CAP`].
struct LineBuilder {
    lines: Vec<Vec<Cell>>,
    cur: Vec<Cell>,
    /// Viewport wrap width (the floor for every override).
    base_width: usize,
    /// CSS `width` overrides of the enclosing blocks (cells).
    widths: Vec<usize>,
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
            base_width: width.max(1),
            widths: Vec::new(),
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

    /// The wrap width in effect (innermost CSS `width` or the viewport).
    fn width(&self) -> usize {
        self.widths
            .last()
            .copied()
            .unwrap_or(self.base_width)
            .max(1)
    }

    /// Enter a CSS-width block: the wrap width changes on a fresh line.
    fn push_width(&mut self, cells: usize) {
        self.flush();
        if self.widths.len() < WIDTH_STACK_CAP {
            self.widths.push(cells.max(1));
        }
    }

    /// Leave the innermost CSS-width block.
    fn pop_width(&mut self) {
        self.flush();
        self.widths.pop();
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
        let indent = self.indent.min(self.width().saturating_sub(1));
        for _ in 0..indent {
            self.cur.push(Cell {
                ch: ' ',
                s: S::normal(),
            });
            self.line_start += 1;
        }
        if let Some(marker) = self.pending_marker.take() {
            for ch in marker.chars() {
                if self.cur.len() >= self.width() {
                    break;
                }
                self.cur.push(Cell { ch, s: S::normal() });
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
        let before = match &b {
            Blk::Para { before, .. }
            | Blk::Heading { before, .. }
            | Blk::Pre { before, .. }
            | Blk::Div { before, .. }
            | Blk::ListItem { before, .. } => *before,
        };
        // CSS top margin/padding as real blank lines (bounded),
        // emitted before the block starts a line.
        for _ in 0..before.min(BLOCK_SPACE_CAP) {
            self.blank();
        }
        match b {
            Blk::Para { indent, .. } | Blk::Heading { indent, .. } => {
                // Separate consecutive blocks with one blank line, but
                // never start the document with one.
                if matches!(self.lines.last(), Some(l) if !l.is_empty()) {
                    self.blank();
                }
                self.indent = indent;
                self.pre = false;
                self.pending_marker = None;
            }
            Blk::Pre { indent, .. } => {
                self.indent = indent;
                self.pre = true;
                self.pending_marker = None;
            }
            Blk::Div { indent, .. } => {
                self.indent = indent;
                self.pre = false;
                self.pending_marker = None;
            }
            Blk::ListItem { marker, indent, .. } => {
                self.indent = indent;
                self.pre = false;
                self.pending_marker = marker;
                // The marker line exists even for an empty item; with
                // `list-style-type: none` nothing is forced (the item's
                // text starts the line instead).
                if self.pending_marker.is_some() {
                    self.ensure_line();
                }
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
            .width()
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
            let avail = self.width().saturating_sub(self.cur.len());
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
            if self.cur.len() >= self.width() {
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
    // One parse per render (docs/browser.md §5): every `<style>`
    // subtree's text, then the cascade per element during the walk.
    let sheet = Stylesheet::parse(&collect_styles(doc));
    let items = flatten(doc, &sheet, width);
    let mut builder = LineBuilder::new(width, cap);
    for item in items {
        match item {
            Item::Block(b) => builder.block(b),
            Item::Text(t, s) => builder.text(&t, s),
            Item::Break => builder.br(),
            Item::PushWidth(cells) => builder.push_width(cells),
            Item::PopWidth => builder.pop_width(),
        }
    }
    builder.finish()
}

// ---------------------------------------------------------------------------
// Rendering through the A1 screen layer
// ---------------------------------------------------------------------------

/// Semantic style → the explicit VGA attribute pair `(fg, bg)` wrapped
/// in ratatui `Color::Indexed` (so `VgaBackend::colors` passes the
/// indices through untouched). With no CSS overlay this produces
/// exactly B2's attribute bytes:
///
/// | base | fg | bg | attr |
/// |---|---|---|---|
/// | Normal | 7 | 0 | 0x07 |
/// | Heading(1–2) | 7 + bright | 0 | 0x0F |
/// | Heading(3–6) | 8 | 0 | 0x08 |
/// | Bold | 7 + bright | 0 | 0x0F |
/// | Code | 8 | 0 | 0x08 |
/// | Link (inverse) | 0 | 7 | 0x70 |
///
/// CSS adds `color` (fg), `background-color` (bg), `font-weight` (the
/// bright bit, the only "bold" text mode has) and `font-style: italic`
/// (the dim half — VGA has no italics). Underline/blink are dropped
/// (documented in `apps/tui.rs`).
fn rs(s: S) -> Style {
    let mut fg = match (s.base, s.fg) {
        (_, Some(fg)) => fg,
        (Base::Code, None) | (Base::Heading(3..=6), None) => 0x08,
        _ => 0x07,
    };
    let mut bg = s.bg.unwrap_or(0x00);
    let bold = s
        .bold
        .unwrap_or(matches!(s.base, Base::Heading(_) | Base::Bold));
    if bold && fg < 8 {
        fg |= 0x08;
    }
    if s.dim {
        fg &= 0x07;
    }
    if matches!(s.base, Base::Link) {
        core::mem::swap(&mut fg, &mut bg);
    }
    Style::new().fg(Color::Indexed(fg)).bg(Color::Indexed(bg))
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
                spans.push(Span::styled(run, rs(run_style.unwrap_or(S::normal()))));
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

// ---------------------------------------------------------------------------
// The B3 proof: BROWSER_CSS_OK
// ---------------------------------------------------------------------------

/// Attributes the CSS fixture asserts (all derived from `csscore`'s
/// documented color mapping — the host tests pin the same values).
/// `color: red` on a plain element → index 1.
const CSS_RED_ATTR: u8 = 0x01;
/// An `h1` with `color: red`: the heading's bold base sets the bright
/// bit → 1 | 8.
const CSS_HEADING_ATTR: u8 = 0x09;
/// `.box { background-color: yellow }` → bg 11, default fg 7.
const CSS_NOTE_ATTR: u8 = 0xB7;
/// `font-weight: 700` / `<strong>` → bright default foreground.
const CSS_BOLD_ATTR: u8 = 0x0F;
/// `#lead { color: cyan }` → 14 (already bright) over `.note`'s green.
const CSS_ID_ATTR: u8 = 0x0E;
/// Inline `color: yellow` → 11, beating the type rule's white.
const CSS_INLINE_ATTR: u8 = 0x0B;
/// Unstyled cells: light grey on black.
const CSS_DEFAULT_ATTR: u8 = 0x07;
/// An unstyled `h1`: B2's plain heading attribute (bold default fg).
const CSS_HEADING_PLAIN_ATTR: u8 = 0x0F;
/// `margin-left: 16px` (2 cells) + `padding-left: 2` (2 cells).
const CSS_SHIFT_CELLS: usize = 4;

/// The fixture's stylesheet: every B3 feature plus the specificity
/// matrix (type < class < id, source order, inline, descendant,
/// compound, `!important` is host-tested in `csscore`).
const CSS_FIXTURE_STYLE: &str = "<style>\
h1 { color: #ffffff }\
h1 { color: red }\
.box { background-color: yellow }\
p { display: none }\
.red { color: red }\
strong { font-weight: 700 }\
.shift { margin-left: 16px; padding-left: 2 }\
span { color: #ffffff }\
.note { color: green }\
#lead { color: cyan }\
span.note { font-weight: bold }\
.outer span { color: red }\
</style>";

/// The fixture body — deterministic, kernel-owned, no network.
const CSS_FIXTURE_BODY: &str = "<h1>Styled heading</h1>\
<div class=\"box\">NOTE BLOCK TEXT</div>\
<p>HIDDEN PARAGRAPH</p>\
<div class=\"red\">RED TEXT</div>\
<div><strong>Bold text</strong></div>\
<div class=\"shift\">SHIFTED TEXT</div>\
<div><span class=\"note\" id=\"lead\">ID BEATS CLASS</span></div>\
<div class=\"outer\"><span>DESCENDANT TEXT</span></div>\
<div><span style=\"color: yellow\">INLINE TEXT</span></div>";

/// The fixture with or without its stylesheet — the pair is the
/// "styled differs from unstyled" proof.
fn css_fixture(styled: bool) -> String {
    let mut html = String::from("<title>css fixture</title>");
    if styled {
        html.push_str(CSS_FIXTURE_STYLE);
    }
    html.push_str(CSS_FIXTURE_BODY);
    html
}

/// The B3 boot proof (docs/browser.md §5/§7 row B3): render the CSS
/// fixture **with** its sheet, read the attribute bytes and positions
/// back from `0xb8000`, then render the identical body **without** the
/// sheet and prove the defaults came back — the styled frame differs,
/// machine-checked. Finally the real page (when supplied) is rendered
/// once more with its own stylesheet for robustness (no assertion on
/// wire CSS). Prints `BROWSER_CSS_OK` between `BROWSER_RENDER_OK` and
/// `SHELL_OK`; `FATAL: browser:` + [`crate::halt`] on any mismatch,
/// and a clean text screen for the shell afterwards.
pub fn css_boot_proof(real: Option<&[u8]>) {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: browser: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove_css(real) {
        serial_println!("FATAL: browser: {why}");
        crate::halt();
    }
    serial_println!("BROWSER_CSS_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// The three CSS frames plus every readback assertion.
fn prove_css(real: Option<&[u8]>) -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the browser frame (min 50x16)");
    }

    // Frame 1 — the styled fixture: colors, background, bold, the
    // margin/padding shift and the display:none skip.
    let styled = css_fixture(true);
    draw_page(styled.as_bytes(), "css fixture", cols)?;
    if !row_holds(0, b"css fixture") {
        return Err("css fixture title missing from the title bar");
    }
    let Some((x, y)) = locate(b"Styled heading") else {
        return Err("styled heading missing from the viewport");
    };
    if attr_at(x, y) != Some(CSS_HEADING_ATTR) {
        return Err("h1 color did not map to the bright-red VGA attribute");
    }
    let Some((x, y)) = locate(b"NOTE BLOCK TEXT") else {
        return Err("background-color fixture text missing");
    };
    if !run_holds_attr(x, y, b"NOTE BLOCK TEXT", CSS_NOTE_ATTR) {
        return Err("background-color did not paint every cell of the block");
    }
    if screen_anywhere(b"HIDDEN PARAGRAPH") {
        return Err("display:none paragraph was rendered");
    }
    let Some((x, y)) = locate(b"RED TEXT") else {
        return Err("color fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_RED_ATTR) {
        return Err("color did not map to the red VGA attribute");
    }
    let Some((x, y)) = locate(b"Bold text") else {
        return Err("bold fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_BOLD_ATTR) {
        return Err("font-weight: 700 did not set the bright attribute");
    }
    let Some((x, _)) = locate(b"SHIFTED TEXT") else {
        return Err("margin/padding fixture text missing");
    };
    if x != CSS_SHIFT_CELLS {
        return Err("margin-left/padding-left did not shift the text by 4 cells");
    }
    let Some((x, y)) = locate(b"ID BEATS CLASS") else {
        return Err("specificity fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_ID_ATTR) {
        return Err("id specificity did not beat class+type (or bold missing)");
    }
    let Some((x, y)) = locate(b"DESCENDANT TEXT") else {
        return Err("descendant-selector fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_RED_ATTR) {
        return Err("descendant selector did not win over the type rule");
    }
    let Some((x, y)) = locate(b"INLINE TEXT") else {
        return Err("inline-style fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_INLINE_ATTR) {
        return Err("inline style did not beat the stylesheet");
    }

    // Frame 2 — the identical body without its sheet: the styles must
    // be gone (this is the "styled differs from unstyled" assertion).
    let plain = css_fixture(false);
    draw_page(plain.as_bytes(), "css fixture", cols)?;
    let Some((x, y)) = locate(b"Styled heading") else {
        return Err("unstyled heading missing");
    };
    if attr_at(x, y) != Some(CSS_HEADING_PLAIN_ATTR) {
        return Err("unstyled heading is not the plain heading attribute");
    }
    let Some((x, y)) = locate(b"RED TEXT") else {
        return Err("unstyled color fixture text missing");
    };
    if attr_at(x, y) != Some(CSS_DEFAULT_ATTR) {
        return Err("unstyled text is not the default attribute");
    }
    if !screen_anywhere(b"HIDDEN PARAGRAPH") {
        return Err("unstyled fixture lost its paragraph (CSS leaked without a sheet)");
    }
    let Some((x, _)) = locate(b"SHIFTED TEXT") else {
        return Err("unstyled shift text missing");
    };
    if x != 0 {
        return Err("unstyled fixture text is shifted (CSS leaked without a sheet)");
    }

    // Frame 3 — the real page with its own sheet (robustness only:
    // nothing is asserted about wire CSS; today's example.com carries
    // only properties outside the B3 subset, so this frame equals B2's).
    if let Some(html) = real {
        let doc = dom::build(html).map_err(|e| e.as_str())?;
        let sheet = Stylesheet::parse(&collect_styles(&doc));
        serial_println!(
            "browser: css: real page stylesheet parsed ({} rules)",
            sheet.rule_count()
        );
        draw_page(html, "css robustness", cols)?;
        if !row_holds(0, b"Example Domain") {
            return Err("real page lost its title with CSS applied");
        }
    }
    Ok(())
}

/// First `(x, y)` of the actual text buffer holding `needle` as
/// consecutive glyph bytes. Bounded by the screen geometry.
fn locate(needle: &[u8]) -> Option<(usize, usize)> {
    let (cols, rows) = screen::dims()?;
    if needle.is_empty() || needle.len() > cols {
        return None;
    }
    for y in 0..rows {
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
                return Some((x, y));
            }
        }
    }
    None
}

/// The attribute byte of one cell, or `None` out of range.
fn attr_at(x: usize, y: usize) -> Option<u8> {
    crate::vga::peek_cell(x, y).map(|(_, attr)| attr)
}

/// Do the cells of `needle` starting at `(x, y)` all carry `attr`?
fn run_holds_attr(x: usize, y: usize, needle: &[u8], attr: u8) -> bool {
    needle.iter().enumerate().all(|(i, _)| {
        x.checked_add(i)
            .and_then(|cell| attr_at(cell, y))
            .is_some_and(|got| got == attr)
    })
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
