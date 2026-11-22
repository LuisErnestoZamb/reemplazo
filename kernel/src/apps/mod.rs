//! Full-screen application layer (docs/ai-client.md §4, milestones A1
//! and A2).
//!
//! Everything an app draws goes through [`screen`] — the off-screen
//! cell buffer diffed into the VGA text buffer — and [`tui`] wraps
//! that layer in a ratatui `Backend` (official no_std, probed in the
//! A1 commit) plus the first full-screen frame. [`editor`] (A2) builds
//! on both: the gap-buffer text editor rendered through the same
//! `VgaBackend`.
//!
//! These modules move to userland behind syscalls when that milestone
//! lands (documented in docs/ai-client.md §1 — deliberate, not an
//! accident).

pub mod ai;
pub mod editor;
pub mod screen;
pub mod tui;
