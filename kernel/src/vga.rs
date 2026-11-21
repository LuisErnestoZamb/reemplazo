//! VGA text console: mirror every console line onto the legacy text
//! buffer GRUB leaves behind (the boot log's `framebuffer 0xb8000
//! 80x25x16 pitch=160 kind=2` — Multiboot2 type2 = EGA text).
//!
//! Why this exists: the MacBook has no exposed serial port, so the
//! serial console (the development path, `-serial stdio`) is invisible
//! on real hardware — without a text-mode mirror a real boot would be a
//! black screen after GRUB. `crate::serial_print!` writes to **both**
//! sinks; the serial side keeps being the smoke harness's channel.
//!
//! Scope:80×25 cells,2 bytes/cell (char + attribute), light grey on
//! black, scrollback of one screen (lines move up when the cursor
//! passes the last row). No cursor hiding/color control yet — the
//! keyboard milestone's line editing drives it through the same byte
//! stream (`\x08` moves the cursor back, so the shell's
//! backspace-space-backspace erase works here too).

use core::fmt;

/// Bytes per text cell (character + attribute).
const CELL: usize = 2;
/// Default attribute: light grey on black (VGA color byte).
const ATTR: u8 = 0x07;

/// Cursor state over one text buffer.
struct TextConsole {
    base: *mut u8,
    cols: usize,
    rows: usize,
    /// Next cell index (row-major); `cols * rows` means "scroll".
    cursor: usize,
    /// ANSI escape state: 0 none, 1 after ESC, 2 inside a CSI
    /// (`ESC [ … final`). Terminal sequences (`clear`'s `ESC[2J`,
    /// color codes) are swallowed — the text buffer shows glyphs, not
    /// escapes.
    esc: u8,
}

/// Escape states for [`TextConsole::esc`].
const ESC: u8 = 1;
const CSI: u8 = 2;

impl TextConsole {
    fn put(&mut self, byte: u8) {
        match byte {
            b'\n' => {
                let col = self.cursor % self.cols;
                self.cursor += self.cols - col; // start of next row
            }
            b'\r' => {
                let row = self.cursor / self.cols;
                self.cursor = row * self.cols; // back to column 0
            }
            0x08 => {
                // The shell's erase sequence (BS, space, BS) drives
                // this: one cell back, overwrite, one cell back.
                self.cursor = self.cursor.saturating_sub(1);
            }
            byte => {
                // SAFETY: cursor < cols*rows is the invariant `scroll`
                // maintains before every store; base..base+cells is
                // the bootloader-reported text buffer (checked in init).
                unsafe {
                    let cell = self.cursor * CELL;
                    core::ptr::write_volatile(self.base.add(cell), byte);
                    core::ptr::write_volatile(self.base.add(cell + 1), ATTR);
                }
                self.cursor += 1;
            }
        }
        self.scroll();
    }

    /// Keep the cursor on screen: when it passes the last cell, move
    /// every line up one row (overlapping copy = memmove) and clear
    /// the new last line.
    fn scroll(&mut self) {
        let cells = self.cols * self.rows;
        if self.cursor < cells {
            return;
        }
        let line = self.cols * CELL;
        // SAFETY: source and destination are inside the same buffer
        // (cursor - cols ≥ 0 because cursor ≥ cols once it scrolls);
        // `core::ptr::copy` handles the overlap.
        unsafe {
            core::ptr::copy(self.base.add(line), self.base, (self.rows - 1) * line);
            core::ptr::write_bytes(self.base.add((self.rows - 1) * line), b' ', line);
        }
        self.cursor = (self.rows - 1) * self.cols;
    }

    fn emit(&mut self, s: &str) {
        for &byte in s.as_bytes() {
            match self.esc {
                // Inside `ESC [ …`: swallow until the final byte
                // (0x40..=0x7E) — covers `clear` (`ESC[2J`, `ESC[H`)
                // and any color codes added later.
                CSI => {
                    if (0x40..=0x7E).contains(&byte) {
                        self.esc = 0;
                    }
                }
                // Just after ESC: `[` starts a CSI, anything else is a
                // simple sequence ending in this byte.
                ESC => {
                    self.esc = if byte == b'[' { CSI } else { 0 };
                }
                _ => {
                    if byte == 0x1B {
                        self.esc = ESC;
                    } else if byte == b'\n'
                        || byte == b'\r'
                        || byte == 0x08
                        || (0x20..=0x7E).contains(&byte)
                    {
                        self.put(byte);
                    }
                    // Other control bytes and non-ASCII are dropped:
                    // the text buffer shows glyphs, not control codes.
                }
            }
        }
    }

    /// Read row0 back and compare it with `expected` — the smoke's
    /// `VGA_OK` proof that init + mirroring landed in the buffer.
    fn holds(&self, expected: &str) -> bool {
        let bytes = expected.as_bytes();
        if bytes.len() > self.cols {
            return false;
        }
        for (i, &want) in bytes.iter().enumerate() {
            // SAFETY: i < expected.len() ≤ cols < cols*rows, inside
            // the buffer `init` validated; volatile reads of our writes.
            let got = unsafe { core::ptr::read_volatile(self.base.add(i * CELL)) };
            if got != want {
                return false;
            }
        }
        true
    }
}

static mut CONSOLE: Option<TextConsole> = None;

/// Bring up the text console over `[addr, addr + cols*rows*2)`.
/// Fail-soft: without a usable text framebuffer (no tag, unexpected
/// pitch) the serial console stays the only output — never panic.
pub fn init(addr: usize, cols: usize, rows: usize, pitch: usize) {
    if cols == 0 || rows == 0 || pitch < cols * CELL || addr == 0 {
        return;
    }
    if addr > usize::MAX - cols * rows * CELL {
        return;
    }
    // SAFETY: `base` covers cols*rows cells inside the reported buffer,
    // identity-mapped (first 4 GiB) by entry.S; single writer.
    unsafe {
        *core::ptr::addr_of_mut!(CONSOLE) = Some(TextConsole {
            base: addr as *mut u8,
            cols,
            rows,
            cursor: 0,
            esc: 0,
        });
    }
}

/// Reconcile with the bootloader's real framebuffer tag: keep the
/// defaults when the tag agrees (GRUB text mode does on our chain —
/// 0xb8000, 80×25, pitch160), rebind when it points elsewhere, and
/// shut the console off for anything that is not EGA text — never
/// write to unknown memory.
pub fn sync(addr: usize, cols: usize, rows: usize, pitch: usize, text: bool) {
    if !text {
        disable();
        return;
    }
    // SAFETY: read-only peek at the current binding (single core,
    // written once by init before any print).
    let current = unsafe { &*core::ptr::addr_of!(CONSOLE) }
        .as_ref()
        .map(|console| (console.base as usize, console.cols, console.rows));
    match current {
        Some((base, c, r)) if base == addr && c == cols && r == rows => {} // agrees: keep cursor
        _ => init(addr, cols, rows, pitch),
    }
}

/// Turn the mirror off (the tag said "not text").
pub fn disable() {
    // SAFETY: single core; the console is only ever written by
    // init/sync/disable during early boot.
    unsafe {
        *core::ptr::addr_of_mut!(CONSOLE) = None;
    }
}

/// Does row0 of the text buffer start with `expected`? The smoke's
/// `VGA_OK` assertion (see [`TextConsole::holds`]).
pub fn verify(expected: &str) -> bool {
    // SAFETY: read-only peek; single core, `init` ran before prints.
    unsafe { &*core::ptr::addr_of!(CONSOLE) }
        .as_ref()
        .is_some_and(|console| console.holds(expected))
}

/// One formatted write to the text buffer, if present. Called by
/// `serial_print!` next to the UART write; never fails.
pub fn mirror(args: fmt::Arguments<'_>) {
    // SAFETY: CONSOLE is written once by `init` during early boot,
    // before any mirrored print; single core (IRQ0 handlers never
    // print — see serial.rs).
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
    if let Some(console) = console {
        use fmt::Write as _;
        let _ = console.write_fmt(args);
    }
}

impl fmt::Write for TextConsole {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.emit(s);
        Ok(())
    }
}
