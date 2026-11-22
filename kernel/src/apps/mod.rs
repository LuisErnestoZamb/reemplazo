//! Full-screen application layer (docs/ai-client.md §4, milestones A1
//! and A2 — plus the browser view of docs/browser.md milestone B2).
//!
//! Everything an app draws goes through [`screen`] — the off-screen
//! cell buffer diffed into the VGA text buffer — and [`tui`] wraps
//! that layer in a ratatui `Backend` (official no_std, probed in the
//! A1 commit) plus the first full-screen frame. [`editor`] (A2) builds
//! on both: the gap-buffer text editor rendered through the same
//! `VgaBackend`, and [`browser`] (B2) renders the fetched page's
//! layout through it. [`browse`] (B4) is the interactive browser on top
//! of that view: link list, history, error pages.
//!
//! These modules move to userland behind syscalls when that milestone
//! lands (documented in docs/ai-client.md §1 — deliberate, not an
//! accident).

pub mod ai;
pub mod browse;
pub mod browser;
pub mod editor;
pub mod launcher;
pub mod screen;
pub mod tui;
