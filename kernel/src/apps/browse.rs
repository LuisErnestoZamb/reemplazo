//! B4 of docs/browser.md (§6 layout, §7 networking, §8 row B4): the
//! **interactive browser** — the `browse` shell builtin, its navigation
//! state (link list, history, scroll) and the `BROWSER_NAV_OK` boot
//! proof.
//!
//! One view over [`crate::apps::browser`] (B2/B3's tree → layout →
//! render path, unchanged) plus the state a browser needs:
//!
//! - **Link navigation**: [`Page`] carries the numbered link list the
//!   layout collected. `Tab`/`n` and `p` cycle the selection (the
//!   selected link's inverse cells turn black-on-yellow, `0x30`; it is
//!   scrolled into view), `Enter` resolves the selected `href` against
//!   the page URL through `url` (relative links work) and loads it.
//! - **History**: [`History`] is a fixed [`HISTORY_CAP`]-slot stack of
//!   parsed `Url`s — no unbounded growth. `b`/`Backspace` goes back,
//!   `f` forward; a **new** navigation drops the forward tail (the
//!   classic rule). Going back/forward re-fetches (no cache — §1's
//!   documented v1 scope), so the entry is the absolute URL.
//! - **Status bar**: history markers (`<`/`>`), the current URL and —
//!   while a link is selected — its target, all printable-ASCII and
//!   clipped to the viewport.
//! - **Scrolling**: arrows, `PageUp`/`PageDown`, `Home`/`End`, clamped
//!   to the laid-out lines; `Esc` returns to the prompt and the screen
//!   self-heals like `tui`/`edit`.
//! - **Error pages**: every navigation failure — bad URL, DNS, refused
//!   connection, timeout, HTTP framing, status, body bound — becomes a
//!   page ("Could not load page" + the cause line + the attempted URL),
//!   never a `FATAL:` and never a hang: [`crate::browser::navigate`] is
//!   the fail-closed fetch with a shorter connect bound, and its
//!   [`crate::browser::NavError`] is what the page shows.
//!
//! # `https` today (documented deviation)
//!
//! `tls.rs` is outside B4's change set and its only entry point
//! (`tls::tls_open`) is **fail-closed by design**: a certificate the
//! pinned single root refuses halts the machine. Handing user-initiated
//! navigation to it would break the "never `FATAL` for user navigation"
//! rule, so [`crate::browser::navigate`] refuses `https` with an error
//! page before any socket work. The fix is a fallible entry point in
//! `tls.rs` (`Result<TlsConnection, TlsError>`) plus a widened trust
//! store; both are recorded in docs/browser.md §8 row B4 and the
//! appendix.
//!
//! # The proof (`BROWSER_NAV_OK`)
//!
//! Deterministic and offline: two **kernel-owned fixture documents**
//! (`fixture://site/a` ↔ `fixture://site/b`, relative hrefs, the custom
//! scheme resolved inside this module) drive the *same* functions the
//! keys call ([`App::open_url`], [`App::key`]) — A renders, Tab selects
//! the link, Enter follows it to B, `b` back to A, `f` forward to B,
//! `b` + Tab + Enter again (a new navigation, so the forward tail must
//! clear), then an unreachable endpoint (`http://10.0.2.2:9/` — the
//! slirp gateway with no service on port 9) must render the **error
//! page** within the bounded connect deadline. Every step reads the
//! frame back from `0xb8000` (the B2/B3 pattern) and asserts the
//! history depths; any mismatch is `FATAL: browser:` + halt.

use crate::apps::browser::{self, Page};
use crate::apps::screen::{self, ScreenError};
use crate::apps::tui::VgaBackend;
use crate::keyboard::Key;
use crate::netstack::Stack;
use alloc::format;
use alloc::string::String;
use ratatui::Terminal;
use url::Url;

/// History slots: fixed (bounded heap — 16 parsed URLs, never grows).
const HISTORY_CAP: usize = 16;
/// Smallest geometry the proof accepts: the fixture frame (title, body,
/// status) needs less than this, but the browser is only usable with
/// room for a page.
const MIN_COLS: usize = 40;
const MIN_ROWS: usize = 10;
/// The fixture site's host (`fixture://site/a`) — the custom scheme's
/// pages never leave this module.
const FIXTURE_HOST: &str = "site";
/// Proof entry: fixture page A.
const FIXTURE_A_URL: &str = "fixture://site/a";
/// The unreachable endpoint of the error-page proof: slirp's gateway
/// address (`10.0.2.2`) with no service on port 9, so the connect is
/// refused/reset (or hits the app's 3 s bound) — never a hang.
const UNREACHABLE_URL: &str = "http://10.0.2.2:9/";
/// The empty document `App` starts from before its first navigation
/// (one line, kernel-owned: it cannot fail to parse).
const BLANK_PAGE: &str = "<title>reemplazo browser</title>";
/// Text the proof asserts in each fixture's body.
const FIXTURE_A_TEXT: &[u8] = b"Page A of the navigation fixture";
const FIXTURE_B_TEXT: &[u8] = b"Page B of the navigation fixture";

/// Fixture page A — links to B with a **relative** href, so following it
/// exercises `Url::join` against `fixture://site/a` (no network, fully
/// deterministic).
const FIXTURE_A: &str = "<title>Nav Fixture A</title>\
<h1>Nav Fixture A</h1>\
<p>Page A of the navigation fixture.</p>\
<p>Link: <a href=\"b\">go to B</a></p>";
/// Fixture page B — the return link.
const FIXTURE_B: &str = "<title>Nav Fixture B</title>\
<h1>Nav Fixture B</h1>\
<p>Page B of the navigation fixture.</p>\
<p>Link: <a href=\"a\">go to A</a></p>";

/// What one key did — the session loop's only reason to redraw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    /// Nothing changed (unhandled key, dead-end back/forward).
    None,
    /// State changed: redraw the frame.
    Redraw,
    /// `Esc`: leave the app.
    Quit,
}

// ---------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------

/// Bounded back/forward stack: [`HISTORY_CAP`] parsed URLs in a fixed
/// array plus the current position. Nothing here allocates beyond the
/// URLs' own storage (at most sixteen of them, freed only when the app
/// drops).
struct History {
    slots: [Option<Url>; HISTORY_CAP],
    /// Number of occupied slots (`0..=HISTORY_CAP`).
    len: usize,
    /// Index of the current entry (`< len` once anything was recorded).
    pos: usize,
}

impl History {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| None),
            len: 0,
            pos: 0,
        }
    }

    /// Record a **new** navigation: drop the forward tail, append, and
    /// make it current. At the cap the oldest entry is discarded (the
    /// stack can never grow past 16).
    fn push(&mut self, url: Url) {
        let mut at = if self.len == 0 {
            0
        } else {
            self.pos.saturating_add(1)
        };
        if at >= HISTORY_CAP {
            // Full: drop the oldest entry and shift the rest down by
            // one. `split_at_mut` + `last_mut`/`first_mut` keeps the
            // copy panic-free (no indexing) for every `i < CAP`.
            for i in 1..HISTORY_CAP {
                let (left, right) = self.slots.split_at_mut(i);
                if let (Some(dst), Some(src)) = (left.last_mut(), right.first_mut()) {
                    *dst = src.take();
                }
            }
            at = HISTORY_CAP - 1;
        }
        // `at < HISTORY_CAP` by construction; `slots` is a fixed array
        // (panics are impossible, and this is not wire input either).
        if let Some(slot) = self.slots.get_mut(at) {
            *slot = Some(url);
        }
        self.len = at.saturating_add(1);
        self.pos = at;
    }

    /// The current entry, cloned (history keeps the original).
    fn current(&self) -> Option<Url> {
        self.slots.get(self.pos).and_then(Option::clone)
    }

    /// Step back, if there is an older entry.
    fn back(&mut self) -> Option<Url> {
        if self.pos == 0 {
            return None;
        }
        self.pos = self.pos.saturating_sub(1);
        self.current()
    }

    /// Step forward, if the forward tail is non-empty.
    fn forward(&mut self) -> Option<Url> {
        if self.pos.saturating_add(1) >= self.len {
            return None;
        }
        self.pos = self.pos.saturating_add(1);
        self.current()
    }

    /// Entries before the current one.
    fn back_depth(&self) -> usize {
        self.pos
    }

    /// Entries after the current one (cleared by a new navigation).
    fn forward_depth(&self) -> usize {
        self.len.saturating_sub(self.pos.saturating_add(1))
    }

    /// Total recorded entries.
    fn depth(&self) -> usize {
        self.len
    }
}

// ---------------------------------------------------------------------------
// The app
// ---------------------------------------------------------------------------

/// The interactive browser state: one rendered [`Page`], its absolute
/// URL, the bounded history, the selected link and the scroll offset —
/// plus the ratatui `Terminal` (its two buffers are allocated once per
/// session, not per frame).
pub(crate) struct App {
    terminal: Terminal<VgaBackend>,
    page: Page,
    /// Absolute URL of the current page (`None` only after a URL that
    /// did not even parse — nothing to resolve relative links against).
    url: Option<Url>,
    /// Printable-ASCII, width-clipped URL for the status bar (and the
    /// error page's "attempted URL" line).
    shown: String,
    history: History,
    /// Selected link index into the page's list (`None` = nothing
    /// selected; `Enter` then does nothing).
    sel: Option<usize>,
    /// First layout line drawn in the viewport.
    top: usize,
    cols: usize,
    rows: usize,
}

impl App {
    /// Open `start` as the first page: the `browse <url>` entry point
    /// (and the proof's first navigation).
    pub(crate) fn open_url(
        start: &str,
        stack: &mut Stack,
        cols: usize,
        rows: usize,
    ) -> Result<Self, &'static str> {
        let terminal = Terminal::new(VgaBackend::default()).map_err(|_| "terminal init failed")?;
        let page = Page::load(BLANK_PAGE.as_bytes(), cols)?;
        let mut app = Self {
            terminal,
            page,
            url: None,
            shown: String::new(),
            history: History::new(),
            sel: None,
            top: 0,
            cols,
            rows,
        };
        app.navigate(start, stack, true);
        Ok(app)
    }

    /// Viewport height in layout lines (title bar + status bar take the
    /// rest).
    fn page_h(&self) -> usize {
        self.rows.saturating_sub(2)
    }

    /// Largest valid scroll offset for the current page.
    fn max_top(&self) -> usize {
        self.page.line_count().saturating_sub(self.page_h())
    }

    /// Draw the current state into the viewport.
    pub(crate) fn draw(&mut self) -> Result<(), &'static str> {
        let status = self.status();
        browser::draw_with(&mut self.terminal, &self.page, &status, self.sel, self.top)
    }

    /// Status-bar text: history markers, the URL, and the selected
    /// link's target. Printable ASCII, clipped to the viewport.
    fn status(&self) -> String {
        let mut out = String::new();
        if let Some(sel) = self.sel
            && self.page.link_count() > 0
        {
            out.push_str(&format!(
                "{}/{} ",
                sel.saturating_add(1),
                self.page.link_count()
            ));
        }
        if self.history.back_depth() > 0 {
            out.push('<');
        }
        if self.history.forward_depth() > 0 {
            out.push('>');
        }
        out.push(' ');
        out.push_str(&self.shown);
        if let Some(sel) = self.sel
            && let Some(target) = self.page.link_target(sel)
        {
            out.push_str(" -> ");
            out.push_str(target);
        }
        browser::sanitize_display(&out, self.cols)
    }

    /// One keystroke — the *only* input path, shared by the session loop
    /// and the boot proof.
    pub(crate) fn key(&mut self, key: Key, stack: &mut Stack) -> Action {
        match key {
            Key::Esc => Action::Quit,
            Key::Up => self.scroll(-1),
            Key::Down => self.scroll(1),
            Key::PageUp => self.scroll(-(self.page_h() as isize)),
            Key::PageDown => self.scroll(self.page_h() as isize),
            Key::Home => {
                self.top = 0;
                Action::Redraw
            }
            Key::End => {
                self.top = self.max_top();
                Action::Redraw
            }
            Key::Tab | Key::Char('n') => self.cycle(1),
            Key::Char('p') => self.cycle(-1),
            Key::Enter => self.enter(stack),
            Key::Char('b') | Key::Backspace => self.back(stack),
            Key::Char('f') => self.forward(stack),
            _ => Action::None,
        }
    }

    /// Scroll by `delta` layout lines, clamped to the page.
    fn scroll(&mut self, delta: isize) -> Action {
        let max = self.max_top();
        let next = if delta < 0 {
            self.top.saturating_sub(delta.unsigned_abs())
        } else {
            self.top.saturating_add(delta.unsigned_abs())
        };
        let clamped = next.min(max);
        if clamped == self.top {
            Action::None
        } else {
            self.top = clamped;
            Action::Redraw
        }
    }

    /// Cycle the selected link (wrapping), scrolling it into view.
    fn cycle(&mut self, delta: isize) -> Action {
        let count = self.page.link_count();
        if count == 0 {
            self.sel = None;
            return Action::None;
        }
        let step = if delta > 0 {
            1
        } else {
            count.saturating_sub(1)
        };
        let next = match self.sel {
            None if delta > 0 => 0,
            None => count.saturating_sub(1),
            Some(current) => current.saturating_add(step) % count,
        };
        self.sel = Some(next);
        // Keep the highlighted link on screen (a bounded scan of the
        // laid-out cells: ≤ LINE_CAP × cols comparisons).
        if let Some(row) = self.page.link_row(next) {
            let page_h = self.page_h();
            if row < self.top {
                self.top = row;
            } else if row >= self.top.saturating_add(page_h) {
                self.top = row.saturating_add(1).saturating_sub(page_h);
            }
            self.top = self.top.min(self.max_top());
        }
        Action::Redraw
    }

    /// Follow the selected link: resolve its `href` against the current
    /// page URL (relative links work) and navigate there.
    fn enter(&mut self, stack: &mut Stack) -> Action {
        let Some(sel) = self.sel else {
            return Action::None;
        };
        let Some(href) = self.page.link_target(sel).map(String::from) else {
            self.sel = None;
            return Action::Redraw;
        };
        let target = match self.url.as_ref() {
            Some(base) => match base.join(&href) {
                Ok(url) => String::from(url.as_str()),
                Err(e) => {
                    serial_println!("browse: cannot resolve a link target: {e:?}");
                    self.show_error("the link target could not be resolved", &href);
                    self.sel = None;
                    self.top = 0;
                    return Action::Redraw;
                }
            },
            // No base (a page reached from an unparseable URL): only an
            // absolute href can be followed.
            None => href,
        };
        self.navigate(&target, stack, true);
        Action::Redraw
    }

    /// `b`: the previous history entry (re-fetched — no cache).
    fn back(&mut self, stack: &mut Stack) -> Action {
        match self.history.back() {
            Some(url) => {
                self.replay(&url, stack);
                Action::Redraw
            }
            None => Action::None,
        }
    }

    /// `f`: the next history entry (the forward tail a new navigation
    /// clears).
    fn forward(&mut self, stack: &mut Stack) -> Action {
        match self.history.forward() {
            Some(url) => {
                self.replay(&url, stack);
                Action::Redraw
            }
            None => Action::None,
        }
    }

    /// `record`: whether this is a new navigation (push onto history) or
    /// a back/forward replay of the entry already current.
    fn navigate(&mut self, target: &str, stack: &mut Stack, record: bool) {
        let parsed = match Url::parse(target) {
            Ok(url) => url,
            Err(e) => {
                serial_println!("browse: cannot parse the URL: {e:?}");
                self.show_error("cannot parse the URL", target);
                self.url = None;
                return;
            }
        };
        if parsed.scheme() == "fixture" {
            match fixture_document(&parsed) {
                Some(html) => self.settle(html.as_bytes(), &parsed, record),
                None => {
                    self.show_error("unknown fixture page", parsed.as_str());
                    self.url = Some(parsed.clone());
                    if record {
                        self.history.push(parsed);
                    }
                }
            }
            return;
        }
        match crate::browser::navigate(stack, parsed.as_str()) {
            Ok(fetched) => {
                // The sample is a static slice; `Page::load` copies what
                // it keeps, so the borrow ends here.
                let html = crate::browser::sample();
                self.settle(html, &fetched.url, record);
            }
            Err(e) => {
                let cause = format!("{e}");
                serial_println!("browse: navigation failed: {cause}");
                self.show_error(&cause, parsed.as_str());
                self.url = Some(parsed.clone());
                if record {
                    self.history.push(parsed);
                }
            }
        }
    }

    /// Install a successfully fetched document as the current page.
    fn settle(&mut self, html: &[u8], url: &Url, record: bool) {
        match Page::load(html, self.cols) {
            Ok(page) => {
                self.page = page;
                self.url = Some(url.clone());
                self.shown = browser::sanitize_display(url.as_str(), self.cols);
                if record {
                    self.history.push(url.clone());
                }
            }
            Err(why) => {
                // A page we cannot build (hostile/unparseable tree): the
                // error page keeps the browser on screen.
                self.show_error(why, url.as_str());
                self.url = Some(url.clone());
                if record {
                    self.history.push(url.clone());
                }
            }
        }
        self.sel = None;
        self.top = 0;
    }

    /// Replace the view with a friendly error page. Never fails the
    /// caller: if even the kernel-owned error document cannot be built
    /// (impossible in practice), the previous page stays on screen.
    fn show_error(&mut self, cause: &str, attempted: &str) {
        let shown = browser::sanitize_display(attempted, self.cols);
        let html = error_html(cause, &shown);
        if let Ok(page) = Page::load(html.as_bytes(), self.cols) {
            self.page = page;
        }
        self.shown = shown;
    }

    // --- proof accessors (the boot proof asserts what the keys did) ---

    /// Total history entries.
    fn depth(&self) -> usize {
        self.history.depth()
    }

    /// Entries behind the current one.
    fn back_depth(&self) -> usize {
        self.history.back_depth()
    }

    /// Entries ahead of the current one.
    fn forward_depth(&self) -> usize {
        self.history.forward_depth()
    }

    /// Links on the current page.
    fn link_count(&self) -> usize {
        self.page.link_count()
    }

    /// Repeat the entry already current (back/forward), without
    /// recording it again.
    fn replay(&mut self, url: &Url, stack: &mut Stack) {
        let target = String::from(url.as_str());
        self.navigate(&target, stack, false);
    }
}

// ---------------------------------------------------------------------------
// Fixtures + error pages
// ---------------------------------------------------------------------------

/// The kernel-owned fixture documents: `fixture://site/a` and `/b`.
/// A custom scheme no other layer knows about — deterministic, offline,
/// and handled entirely here (documented in docs/browser.md §8 B4).
fn fixture_document(url: &Url) -> Option<&'static str> {
    if url.host_str() != Some(FIXTURE_HOST) {
        return None;
    }
    match url.path() {
        "/a" => Some(FIXTURE_A),
        "/b" => Some(FIXTURE_B),
        _ => None,
    }
}

/// The error page: a title, the friendly heading, the cause line and
/// the attempted URL — built from our own fixed ASCII (`cause`) plus
/// printable-ASCII URL text, so only the three markup characters need
/// neutralizing.
fn error_html(cause: &str, url: &str) -> String {
    format!(
        "<title>Navigation error</title>\
         <h1>Could not load page</h1>\
         <p>{}</p>\
         <p>URL: {}</p>\
         <p>Esc exits, b goes back.</p>",
        html_escape(cause),
        html_escape(url)
    )
}

/// Escape `&`, `<` and `>` as entities (`dom` decodes them back into the
/// same glyphs, so the page shows what the message said).
fn html_escape(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// The `browse` builtin
// ---------------------------------------------------------------------------

/// The `browse <url>` shell builtin: open the URL and serve keys until
/// `Esc`. Fails soft like every other builtin — a missing text console
/// or a terminal that cannot start prints one line and returns to the
/// prompt; navigation errors are pages, not failures. When a frame did
/// reach the screen the text buffer is cleared on exit, so the shell
/// resumes on a clean screen.
pub fn run(stack: &mut Stack, start: &str) {
    if start.is_empty() {
        serial_println!("usage: browse <url>");
        return;
    }
    if let Err(why) = screen::open() {
        serial_println!("browse: {why}");
        return;
    }
    let Some((cols, rows)) = screen::dims() else {
        serial_println!("browse: no text console");
        return;
    };
    let mut app = match App::open_url(start, stack, cols, rows) {
        Ok(app) => app,
        Err(why) => {
            serial_println!("browse: {why}");
            return;
        }
    };
    let framed = session(&mut app, stack);
    if framed {
        crate::vga::clear_screen();
    }
}

/// One interactive session. Returns whether any frame reached the
/// screen (only then is the screen cleared on exit).
fn session(app: &mut App, stack: &mut Stack) -> bool {
    if let Err(why) = app.draw() {
        serial_println!("browse: render failed ({why})");
        return false;
    }
    loop {
        let key = next_key();
        match app.key(key, stack) {
            Action::Quit => break,
            Action::Redraw => {
                if let Err(why) = app.draw() {
                    serial_println!("browse: render failed ({why})");
                    break;
                }
            }
            Action::None => {}
        }
    }
    true
}

/// Block until a key arrives: the polled PS/2/USB path first (the
/// QEMU `sendkey` wire and the MacBook keyboard), with a serial
/// fallback so a headless terminal can still drive the app. Serial
/// input maps only whole ASCII bytes — ANSI cursor sequences are not
/// parsed (the same documented limit as `apps::tui`), so an arrow typed
/// over serial is ignored; the arrows live on the keyboard path.
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
        0x09 => Some(Key::Tab),
        b if b.is_ascii_graphic() || b == b' ' => Some(Key::Char(char::from(b))),
        _ => None, // other control bytes and CSI leftovers: ignored
    }
}

// ---------------------------------------------------------------------------
// The boot proof: BROWSER_NAV_OK
// ---------------------------------------------------------------------------

/// The B4 proof (docs/browser.md §8 row B4): render fixture A, follow
/// its link to B, back, forward, then a new navigation (which must clear
/// the forward tail) and finally an unreachable endpoint that must
/// render the error page — every frame read back from `0xb8000`, every
/// history depth asserted. Prints `BROWSER_NAV_OK` between
/// `BROWSER_CSS_OK` and `SHELL_OK`; fail-closed on any mismatch
/// (`FATAL: browser:` + [`crate::halt`]), and leaves the screen clean
/// for the shell.
///
/// Offline by design (fixtures + one refused connect), so it cannot
/// depend on the internet — unlike the B1/B2 fetches.
pub fn boot_proof(stack: &mut Stack) {
    match screen::open() {
        Ok(()) => {}
        Err(ScreenError::NoConsole) => return,
        Err(why) => {
            serial_println!("FATAL: browser: {why}");
            crate::halt();
        }
    }
    if let Err(why) = prove(stack) {
        serial_println!("FATAL: browser: {why}");
        crate::halt();
    }
    serial_println!("BROWSER_NAV_OK"); // machine-checked by `cargo xtask smoke`
    crate::vga::clear_screen();
}

/// Drive the app through the keyboard path and assert every frame. Each
/// error string becomes a `FATAL: browser:` line.
fn prove(stack: &mut Stack) -> Result<(), &'static str> {
    let (cols, rows) = screen::dims().ok_or("screen geometry lost after open")?;
    if cols < MIN_COLS || rows < MIN_ROWS {
        return Err("text screen too small for the navigation proof (min 40x10)");
    }
    let status_row = rows.checked_sub(1).ok_or("no status row")?;

    // 1 — page A: title bar, body, and a fresh one-entry history.
    let mut app = App::open_url(FIXTURE_A_URL, stack, cols, rows)?;
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture A") {
        return Err("fixture A title missing from the title bar");
    }
    if !browser::screen_anywhere(FIXTURE_A_TEXT) {
        return Err("fixture A body missing from the viewport");
    }
    if app.link_count() != 1 {
        return Err("fixture A should carry exactly one link");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (1, 0, 0) {
        return Err("history after the first navigation is wrong");
    }

    // 2 — Tab selects the link: highlighted cells + target in the status
    // bar (the key path the manual session uses).
    if app.key(Key::Tab, stack) != Action::Redraw {
        return Err("Tab did not select a link");
    }
    app.draw()?;
    let Some((x, y)) = browser::locate(b"go to B") else {
        return Err("fixture A link text missing from the viewport");
    };
    if !browser::run_holds_attr(x, y, b"go to B", browser::LINK_SELECTED_ATTR) {
        return Err("the selected link is not highlighted");
    }
    if !browser::row_holds(status_row, b"-> b") {
        return Err("the status bar does not show the selected link's target");
    }

    // 3 — Enter follows the relative href (Url::join) to fixture B.
    if app.key(Key::Enter, stack) != Action::Redraw {
        return Err("Enter did not follow the link");
    }
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture B") {
        return Err("fixture B title missing after following the link");
    }
    if !browser::screen_anywhere(FIXTURE_B_TEXT) {
        return Err("fixture B body missing from the viewport");
    }
    let Some((x, y)) = browser::locate(b"go to A") else {
        return Err("fixture B link text missing from the viewport");
    };
    if !browser::run_holds_attr(x, y, b"go to A", browser::LINK_ATTR) {
        return Err("unselected link cells are not inverse");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (2, 1, 0) {
        return Err("history after following the link is wrong");
    }

    // 4 — `b` back to A, `f` forward to B: the classic pair.
    if app.key(Key::Char('b'), stack) != Action::Redraw {
        return Err("b did not go back");
    }
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture A") {
        return Err("back did not restore fixture A");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (2, 0, 1) {
        return Err("history after going back is wrong");
    }
    if app.key(Key::Char('f'), stack) != Action::Redraw {
        return Err("f did not go forward");
    }
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture B") {
        return Err("forward did not restore fixture B");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (2, 1, 0) {
        return Err("history after going forward is wrong");
    }

    // 5 — a *new* navigation from a back position clears the forward
    // tail: back to A, follow the link again, and the tail is gone.
    if app.key(Key::Char('b'), stack) != Action::Redraw {
        return Err("b did not go back a second time");
    }
    if app.key(Key::Tab, stack) != Action::Redraw {
        return Err("Tab did not select the link after going back");
    }
    if app.key(Key::Enter, stack) != Action::Redraw {
        return Err("Enter did not follow the link after going back");
    }
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture B") {
        return Err("the second navigation did not reach fixture B");
    }
    // The forward tail (fixture B) is dropped, not appended: the stack
    // is A → B again, one back step and no forward one.
    if (app.depth(), app.back_depth(), app.forward_depth()) != (2, 1, 0) {
        return Err("a new navigation did not clear the forward tail");
    }

    // 6 — the error page: an unreachable endpoint must render a page
    // (not halt, not hang) within the bounded connect deadline.
    app.navigate(UNREACHABLE_URL, stack, true);
    app.draw()?;
    if !browser::row_holds(0, b"Navigation error") {
        return Err("the error page title bar is missing");
    }
    if !browser::screen_anywhere(b"Could not load page") {
        return Err("the error page heading is missing");
    }
    if !browser::screen_anywhere(b"connection failed or timed out") {
        return Err("the error page cause line is missing");
    }
    if !browser::screen_anywhere(b"10.0.2.2:9") {
        return Err("the error page does not show the attempted URL");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (3, 2, 0) {
        return Err("an error page is not recorded in history");
    }

    // 7 — history works over an error page too: back lands on fixture B.
    if app.key(Key::Char('b'), stack) != Action::Redraw {
        return Err("b did not go back from the error page");
    }
    app.draw()?;
    if !browser::row_holds(0, b"Nav Fixture B") {
        return Err("back from the error page did not restore fixture B");
    }
    if (app.depth(), app.back_depth(), app.forward_depth()) != (3, 1, 1) {
        return Err("history after leaving the error page is wrong");
    }
    Ok(())
}
