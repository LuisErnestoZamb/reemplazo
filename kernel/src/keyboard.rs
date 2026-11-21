//! Polled i8042 (PS/2) keyboard driver — the QEMU input path.
//!
//! # The MacBook reality (docs/hardware.md §2.1)
//!
//! The target's built-in keyboard is **USB HID, not PS/2**: it attaches
//! to UHCI `00:1d.0` as Apple `05ac:021a/021b` ("Apple Internal Keyboard
//! / Trackpad"), and Linux reports *no PS/2 controller at all* on this
//! machine (`i8042: PNP: No PS/2 controller found.`). This driver
//! therefore serves the **QEMU path** — QEMU's `pc` machine always
//! exposes an i8042 at ports `0x60`/`0x64`. On the MacBook, [`init`]
//! fails soft: every wait is bounded, nothing panics, and keyboard input
//! stays unavailable until the later **UHCI + HID** milestone (§2.7
//! step 7). Ports `0x60`/`0x64` are unclaimed there, so a status read
//! floats to `0xFF` and bring-up bails out immediately (§2.1).
//!
//! # Scope (hardware.md §2.7 steps 2–3 — polled first, no IRQ)
//!
//! - **Polled**: the shell loop calls [`next_char`] whenever the serial
//!   UART has nothing to read. IRQ1 (vector 33) stays masked and no
//!   interrupt handler exists yet — that is step 4 (§2.5), later.
//! - Bring-up performs the read/modify/write of the controller config
//!   byte from §2.3: set **bit 6 (KCC/translation)** so the wire
//!   protocol is deterministic **scan code set 1** regardless of what
//!   SeaBIOS/GRUB left behind (§2.2), set **bit 0 (IRQ1)** so the later
//!   handler has a configured source, clear **bit 1 (IRQ12)** and keep
//!   the interfaces enabled. Aux (mouse) bytes are discarded while
//!   polling; IRQ12 never fires because the PIC masks it.
//! - Command **`0xFE` is never sent** — QEMU treats it as a VM reset
//!   request (§2.3).
//! - Decoding — make/break, sticky `E0` prefixes, Shift (both keys) and
//!   CapsLock state, US layout — is the `pc-keyboard` crate
//!   (`ScancodeSet1` + `Us104Key`), evaluated in
//!   `docs/pc-keyboard-eval.md`. Keys with no ASCII mapping (F-keys,
//!   arrows, Win/Menu, media keys) decode to `RawKey` and are ignored.

use crate::port::{inb, outb};
use core::sync::atomic::{AtomicBool, Ordering};
use pc_keyboard::layouts::Us104Key;
use pc_keyboard::{DecodedKey, HandleControl, PS2Keyboard, ScancodeSet1};

const DATA_PORT: u16 = 0x60; // read: output buffer; write: data byte
const STATUS_PORT: u16 = 0x64; // read: status register; write: command register

// Status register bits (QEMU `KBD_STAT_*`, hardware.md §2.3).
const OBF: u8 = 0x01; // output buffer full — the poll bit
const IBF: u8 = 0x02; // input buffer full — controller busy
const AUX_OBF: u8 = 0x20; // pending byte is from the mouse channel

// Controller config byte bits (QEMU `KBD_MODE_*`).
const CFG_KBD_INT: u8 = 0x01; // keyboard data raises IRQ1
const CFG_MOUSE_INT: u8 = 0x02; // aux data raises IRQ12 (cleared: we don't want it)
const CFG_KBD_DISABLE: u8 = 0x10; // keyboard interface disabled
const CFG_MOUSE_DISABLE: u8 = 0x20; // aux interface disabled
const CFG_TRANSLATE: u8 = 0x40; // KCC: set 2 → set 1 translation (the bit we set)

// Controller commands (write to 0x64).
const CMD_READ_CFG: u8 = 0x20; // reply: config byte at 0x60
const CMD_WRITE_CFG: u8 = 0x60; // next 0x60 write is the new config byte
const CMD_ENABLE_KBD: u8 = 0xAE; // enable the keyboard interface

// Keyboard-side command (write to 0x60).
const KBD_ENABLE_SCAN: u8 = 0xF4; // reply: 0xFA ACK
const KBD_ACK: u8 = 0xFA;

/// Upper bound for every controller poll. Each iteration is one `in`
/// (a few hundred ns on the T7400), so a full wait is well under
/// 100 ms — far longer than any real i8042 needs (IBF clears in
/// microseconds, keyboard replies in milliseconds) and short enough
/// that a missing controller (§2.1) cannot stall boot. Bounded waits
/// are the fail-soft contract: no `while` here may spin forever.
const POLL_LIMIT: u32 = 100_000;
/// Bytes dropped when flushing a stale output buffer at bring-up.
const FLUSH_LIMIT: u32 = 256;

/// Set once [`init`] configures the controller; keeps [`next_char`]'s
/// fast path a single relaxed load when there is no keyboard.
static AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Set-1 → Unicode decoder (Shift/CapsLock state lives inside it).
/// `static mut` + raw-pointer access because the decoder needs `&mut`
/// and the kernel has no interior-mutability wrapper yet; the access
/// contract is documented on [`next_char`].
static mut DECODER: PS2Keyboard<Us104Key, ScancodeSet1> =
    PS2Keyboard::new(ScancodeSet1::new(), Us104Key, HandleControl::Ignore);

/// i8042 bring-up (hardware.md §2.3): bounded probe, flush, config
/// byte read/modify/write (IRQ1 + translation), interface enable,
/// keyboard scan-enable. On failure it prints why and leaves the
/// keyboard unavailable: the MacBook's expected outcome (§2.1), never
/// a panic — the smoke test then fails on the missing `KEYBOARD_OK`.
pub fn init() {
    match configure() {
        Ok(()) => {
            AVAILABLE.store(true, Ordering::Relaxed);
            serial_println!("keyboard: i8042 ready (translation on → scancode set 1)");
        }
        Err(why) => serial_println!(
            "keyboard: no i8042 controller ({why}) — PS/2 input disabled \
             (MacBook: built-in keyboard is USB HID, UHCI milestone)"
        ),
    }
}

/// Poll one decoded character, if a keystroke is waiting. `None` means
/// "nothing this iteration" — no controller, output buffer empty, a
/// mouse byte (discarded), an `E0`/`E1` prefix byte, a modifier-only
/// event, or a key with no ASCII mapping. Called from the shell loop.
pub fn next_char() -> Option<char> {
    if !AVAILABLE.load(Ordering::Relaxed) {
        return None;
    }
    let st = status();
    if st & OBF == 0 {
        return None;
    }
    if st & AUX_OBF != 0 {
        let _ = read_data(); // mouse byte: drop it (IRQ12 stays masked)
        return None;
    }
    let byte = read_data(); // reading 0x60 also clears OBF (§2.2)

    // SAFETY: the decoder has exactly one consumer — the shell's idle
    // loop — and no IRQ handler touches it (polled milestone; IRQ1 is
    // still masked in the PIC), so no re-entry or aliasing is possible.
    let decoder = unsafe { &mut *core::ptr::addr_of_mut!(DECODER) };
    // Err = unknown scancode (ignored, decoder state already reset),
    // None = E0/E1 prefix byte consumed.
    let event = decoder.add_byte(byte).ok().flatten()?;
    match decoder.process_keyevent(event)? {
        DecodedKey::Unicode(c) if c.is_ascii() => Some(c),
        _ => None, // RawKey: modifiers, F-keys, arrows, media keys — ignore
    }
}

/// The full §2.3 sequence, with every wait bounded.
fn configure() -> Result<(), &'static str> {
    // No controller? On the MacBook the ports float to 0xFF (§2.1).
    if status() == 0xFF {
        return Err("status reads 0xFF");
    }
    if !wait_ibf_clear() {
        return Err("IBF never clears");
    }
    flush();

    // Read the config byte instead of assuming either firmware state —
    // SeaBIOS/GRUB may have left translation on or off (§2.2 caveat).
    if !send_cmd(CMD_READ_CFG) {
        return Err("read-config command not accepted");
    }
    if !wait_obf() {
        return Err("no config-byte reply");
    }
    let mut cfg = read_data();

    // §2.3 step 3: IRQ1 + translation on; IRQ12 off; interfaces on.
    // On QEMU this flips the byte stream to set 1 (§2.2).
    cfg |= CFG_KBD_INT | CFG_TRANSLATE;
    cfg &= !(CFG_MOUSE_INT | CFG_KBD_DISABLE | CFG_MOUSE_DISABLE);

    if !send_cmd(CMD_WRITE_CFG) || !write_data(cfg) {
        return Err("config byte not writable");
    }
    if !send_cmd(CMD_ENABLE_KBD) {
        return Err("keyboard interface not enableable");
    }

    // Belt and braces (§2.3 step 5): tell the keyboard to enable
    // scanning. QEMU's keyboard already scans, so a missing 0xFA ACK is
    // non-fatal — we bound the wait and move on.
    if write_data(KBD_ENABLE_SCAN) {
        for _ in 0..POLL_LIMIT {
            if status() & OBF == 0 {
                core::hint::spin_loop();
                continue;
            }
            if read_data() == KBD_ACK {
                break;
            }
        }
    }
    Ok(())
}

#[inline]
fn status() -> u8 {
    // SAFETY: 0x64 is the standard i8042 status port; reading an
    // absent controller returns 0xFF, which `configure` treats as
    // "no device". Polled port I/O cannot violate memory safety.
    unsafe { inb(STATUS_PORT) }
}

/// Wait (bounded) for the controller's input buffer to accept a write.
fn wait_ibf_clear() -> bool {
    for _ in 0..POLL_LIMIT {
        if status() & IBF == 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait (bounded) for a reply byte to arrive at 0x60.
fn wait_obf() -> bool {
    for _ in 0..POLL_LIMIT {
        if status() & OBF != 0 {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn read_data() -> u8 {
    // SAFETY: standard i8042 data port; polled, single reader (the
    // shell loop) — no concurrent reader can race us.
    unsafe { inb(DATA_PORT) }
}

/// Send a controller command to 0x64, waiting for IBF to clear first
/// (§2.3 step 1 — a write while IBF is set is dropped by the chip).
fn send_cmd(cmd: u8) -> bool {
    if !wait_ibf_clear() {
        return false;
    }
    // SAFETY: contract of this helper — caller established a live
    // controller via `configure`'s probe; `out` to 0x64 is the
    // documented command interface. Never used for 0xFE (§2.3).
    unsafe { outb(STATUS_PORT, cmd) };
    true
}

/// Write a data byte to 0x60, waiting for IBF to clear first.
fn write_data(val: u8) -> bool {
    if !wait_ibf_clear() {
        return false;
    }
    // SAFETY: as `send_cmd` — live controller, data port 0x60.
    unsafe { outb(DATA_PORT, val) };
    true
}

/// Drain whatever sits in the output buffer (§2.3 step 2), bounded.
/// Aux (mouse) bytes are dropped too — we never read the mouse.
fn flush() {
    for _ in 0..FLUSH_LIMIT {
        if status() & OBF == 0 {
            break;
        }
        let _ = read_data();
    }
}
