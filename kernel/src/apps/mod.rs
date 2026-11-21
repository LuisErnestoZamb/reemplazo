//! Full-screen application layer (docs/ai-client.md §4, milestone A1).
//!
//! Everything an app draws goes through [`screen`] — the off-screen
//! cell buffer diffed into the VGA text buffer — and [`tui`] wraps
//! that layer in a ratatui `Backend` (official no_std, probed in this
//! milestone's commit) plus the first full-screen frame.
//!
//! These modules move to userland behind syscalls when that milestone
//! lands (documented in docs/ai-client.md §1 — deliberate, not an
//! accident).

pub mod screen;
pub mod tui;
