# Dependency evaluation — PS/2 keyboard decoding (`pc-keyboard`)

**Date:** 2026-11-21 · **Milestone:** keyboard input (polled i8042 → shell) ·
**Policy:** use well-known, battle-tested crates; from-scratch only under exception **(a)** the
known crate doesn't support what we need, or **(b)** a from-scratch version offers a worthwhile
memory/CPU/RAM win on the target (same policy as `docs/dependencies.md`).

## Verdict: **use `pc-keyboard`** ✅ — no exception needed

| Check | Result |
|---|---|
| Version | **0.9.0** (latest; `cargo info pc-keyboard`, queried 2026-11-21) |
| `no_std` | ✅ `#![cfg_attr(not(test), no_std)]` in `src/lib.rs` |
| Heap / `alloc` | ❌ none — stateful decoder over caller-provided bytes, no allocation |
| Runtime dependencies | **0** — `cargo tree --target x86_64-unknown-none` shows `pc-keyboard` alone |
| License | MIT OR Apache-2.0 |
| MSRV | 1.61 (our pinned toolchain is 1.98.1) |
| RustSec | **no advisory** — local clone of <https://rustsec.org/advisories/> (`~/.cargo/advisory-db`, commit `55e1c3dfb`, 2026-11-19) contains no entry for `pc-keyboard` / `pc_keyboard` |
| Maintenance | rust-embedded-community (same org as `linked-list-allocator`); repo pushed 2026-05-01, ★115, 15 reverse dependencies, 642 k downloads (crates.io API, 2026-11-21) |
| Fits our feature set | ✅ `ScancodeSet1` (make = code, break = code\|0x80, sticky `E0`/`E1` state), `layouts::Us104Key` (US layout incl. shifted punctuation), Shift **and** CapsLock tracking (caps toggles on make only, per hardware.md §2.4), `HandleControl::Ignore` so Ctrl doesn't mangle letters, media/F-keys/arrows decode to `DecodedKey::RawKey` → ignored gracefully |

## How it was verified (build probe, temp dir — no workspace changes until adopted)

1. **Scratch cross-build:** a throwaway `#![no_std]` crate in the session temp dir depending on
   `pc-keyboard = "0.9.0"`, built with `cargo build --target x86_64-unknown-none` → **success**,
   zero dependencies in the target tree.
2. **Scratch host test** (same probe crate): fed real set-1 byte sequences through
   `PS2Keyboard::new(ScancodeSet1::new(), Us104Key, HandleControl::Ignore)` and asserted the
   decoded chars: `1E` → `a`; `2A 1E 9E AA` (shift-a) → `A`; caps-lock make → `a` becomes `A`
   and stays off after break (caps toggles on make only); `2A 0C …` (shift-minus) → `_`;
   `1C` → `'\n'`, `0E` → `'\x08'`, `39` → `' '`; `E0 48` (arrow up) and `E0 20` (mute) → no
   char (ignored); unknown scancode `00` → ignored **without wedging the decoder**; and the
   smoke test's exact byte sequence for `echo KEYBOARD_OK⏎` → the string
   `"echo KEYBOARD_OK\n"`. All passed (`cargo test`: 1 passed).
3. **Source inspection:** `add_byte` resets its `E0`/`E1` state *before* mapping, so an unknown
   scancode returns `Err` without desyncing; `PS2Keyboard::new` is a `const fn` → usable as a
   `static` in the kernel; only `KeyState::Down` events are mapped to Unicode (breaks produce
   nothing).

## What stays ours (not delegated to the crate)

- The **i8042 port layer** (`kernel/src/keyboard.rs`): bounded IBF/OBF waits, config-byte
  read/modify/write (KCC/translation → deterministic set 1, hardware.md §2.3), aux-byte
  discard, fail-soft "no controller" detection for the MacBook (§2.1), `0xFE` never sent.
- **Polling and input multiplexing**: `next_char()` is polled by the shell loop and feeds the
  same line discipline as serial (no IRQ1 handler yet — §2.7 step 4, later).
- The crate has no knowledge of our line discipline, echo, or CRLF rules — `shell.rs` owns that.

## Alternatives considered

- **From-scratch set-1 decoder** (the fallback if the probe had failed): rejected under the
  policy — `pc-keyboard` is battle-tested (15 revdeps, org-maintained), already handles the
  E0/E1 state machine and modifier edge cases (both shift keys, caps-on-make-only), and a
  hand-rolled version would offer **no** memory/CPU win (it is a ~1 KiB state machine either
  way) — neither policy exception applies.
- **Other crates:** none comparable — `hidapi`-style crates are std/USB-only (that is the later
  UHCI/HID milestone's problem, where we will likely hand-roll a boot-protocol report parser
  since no `no_std` HID crate is established).
