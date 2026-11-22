//! Top-bar application launcher (ring 0 until the userland milestone).
//!
//! Reserves row 0 of the VGA text console for a one-line menu of the
//! built-in applications. Left/Right (or Tab) move the selection, Enter
//! launches it through the same dispatch as the shell builtins, and Esc
//! returns to the shell. Everything goes through [`screen`]'s staged
//! buffer and [`screen::flush_diff`], so the bar never desyncs the
//! readback the smoke tests assert on `0xb8000`.
//!
//! Fail-soft: with no console geometry the launcher prints a hint on
//! the serial console and returns — it never panics or touches memory
//! outside the text buffer. This module is intentionally small and
//! self-contained: when the apps migrate to userland (`hito 3` of the
//! userland blueprint), only the `launch` callback changes — the bar
//! rendering and navigation can be lifted into a userspace process.

use super::screen;
use crate::install::Payloads;
use crate::keyboard::{self, Key};
use crate::netstack::Stack;

/// Inverse attribute for the selected item (white on black in the
/// standard 16-colour VGA palette); normal items are light grey on
/// black.
const ATTR_SEL: u8 = 0x70;
const ATTR_ITEM: u8 = 0x07;
const ATTR_HINT: u8 = 0x08;

/// One menu entry: a short label shown in the bar and the builtin
/// command line that launches it. The command is passed to the same
/// `shell::execute` path the typed builtins use, so there is exactly
/// one implementation of every app.
struct Entry {
    label: &'static str,
    command: &'static str,
}

const ENTRIES: [Entry; 7] = [
    Entry {
        label: "1:TUI",
        command: "tui",
    },
    Entry {
        label: "2:Edit",
        command: "edit",
    },
    Entry {
        label: "3:AI",
        command: "ai",
    },
    Entry {
        label: "4:Browse",
        command: "browse",
    },
    Entry {
        label: "5:Mem",
        command: "meminfo",
    },
    Entry {
        label: "6:Net",
        command: "netinfo",
    },
    Entry {
        label: "7:Shell",
        command: "", // empty: just close the bar and re-prompt
    },
];

/// Draw the top bar into the staged buffer without flushing: the
/// caller may stage more content (e.g. the hint on row 1) before the
/// single `flush_diff` at the end of a pass.
fn draw(sel: usize) {
    let Some((cols, _rows)) = screen::dims() else {
        return;
    };
    // Fill row 0 with spaces first so shorter bars don't leave stale
    // glyphs behind when the selection label lengths change.
    let mut x = 0usize;
    while x < cols {
        let _ = screen::put(x as u16, 0, ' ', ATTR_ITEM, 0);
        x += 1;
    }
    let mut x = 0usize;
    for (i, e) in ENTRIES.iter().enumerate() {
        if x >= cols {
            break;
        }
        let attr = if i == sel { ATTR_SEL } else { ATTR_ITEM };
        for ch in e.label.chars() {
            if x >= cols {
                break;
            }
            let _ = screen::put(x as u16, 0, ch, attr, 0);
            x += 1;
        }
        if x < cols {
            let _ = screen::put(x as u16, 0, ' ', ATTR_ITEM, 0);
            x += 1;
        }
    }
}

/// Interactive launcher loop. Called from the shell builtin `apps`.
/// Returns when the user picks an app (which is then launched by the
/// caller) or presses Esc (no launch).
pub fn run(stack: &mut Stack, payloads: &Payloads) {
    if screen::open().is_err() {
        crate::serial_println!("apps: no text console (launcher needs VGA)");
        return;
    }
    let mut sel = 0usize;
    draw(sel);
    screen::flush_diff();

    loop {
        match keyboard::next_event() {
            Some(Key::Left) | Some(Key::Tab) => {
                if sel == 0 {
                    sel = ENTRIES.len() - 1;
                } else {
                    sel -= 1;
                }
                draw(sel);
                screen::flush_diff();
            }
            Some(Key::Right) => {
                sel = (sel + 1) % ENTRIES.len();
                draw(sel);
                screen::flush_diff();
            }
            Some(Key::Enter) => {
                let cmd = ENTRIES[sel].command;
                if cmd.is_empty() {
                    // "Shell": just clear the bar and go back.
                    clear_bar();
                    return;
                }
                clear_bar();
                crate::serial_println!("apps: launching {cmd}");
                super::super::shell::execute(stack, payloads, cmd);
                return;
            }
            Some(Key::Esc) => {
                clear_bar();
                return;
            }
            Some(Key::Char('q')) => {
                clear_bar();
                return;
            }
            // Up/Down/Char('1'..='7') are handled as direct shortcuts
            // below; everything else is ignored so fast typing in the
            // shell can't accidentally launch anything.
            Some(Key::Char(c)) if c.is_ascii_digit() => {
                if let Some(i) = c.to_digit(10).and_then(|d| usize::try_from(d - 1).ok())
                    && i < ENTRIES.len()
                {
                    sel = i;
                    draw(sel);
                    screen::flush_diff();
                }
            }
            Some(_) | None => {}
        }
        crate::power::idle();
    }
}

/// Remove the bar from the staged buffer (row 0 → spaces) and flush
/// once, so the shell prompt that follows never inherits stale cells.
fn clear_bar() {
    let Some((cols, _)) = screen::dims() else {
        return;
    };
    let mut x = 0usize;
    while x < cols {
        let _ = screen::put(x as u16, 0, ' ', ATTR_HINT, 0);
        x += 1;
    }
    screen::flush_diff();
}
