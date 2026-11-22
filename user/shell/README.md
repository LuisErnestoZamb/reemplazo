# `user/shell/` — hito 3 console process

First ring-3 process that **owns the console**. `no_std`, no heap, no
allocator. Built by `cargo xtask smoke-user` (its own tiny workspace so the
root `Cargo.toml` member list does not change) and staged in the ISO under
the existing multiboot module name `hello` — that is the only name the
kernel's U1 capture path knows today, so no loader change is needed.

## Flow

1. `console_dims()` — first syscall: claims console ownership and (until
   the hito-2 scheduler publishes VMAs) makes `userptr` accept this
   process's buffers. Also triggers the kernel's lazy `SYSCALL_OK` proof.
2. `vga_put_cell` → `vga_flush` → `vga_peek(0,0)` round-trip against the
   real `0xb8000` cell, then **`USER_CONSOLE_OK`**. No user pointer or
   physical address is ever passed to the kernel.
3. **`USER_SHELL_OK`** and the prompt.
4. `read(0, buf)` loop. No complete line → `0`, so the process yields and
   retries. One line → `help` / `echo` / `uptime` / `apps` / `exit`, then it
   exits so the kernel prints `USER_RETURN_OK`.
   The smoke harness injects `echo KEYBOARD_OK` through QEMU's monitor
   after `USER_SHELL_OK`; the echo builtin's exact output proves the new
   `Read` syscall carried real keystrokes from the i8042/USB wire.

## ABI additions (mirrors `kernel/src/userland/console.rs`)

| # | Name | Args | Success | Failure |
|---|------|------|---------|---------|
| 4 | `read` | `fd=0, buf, len` | byte count, `0` if no line | `-1`, `-2` |
| 5 | `vga_dims` | — | `cols \| rows<<16` | `-1` |
| 6 | `vga_put_cell` | `x, y, glyph, attr` | `0` | `-13`, `-1` |
| 7 | `vga_clear` | — | `0` | `-13` |
| 8 | `vga_flush` | — | `0` | `-13` |
| 9 | `vga_peek` | `x, y` | `glyph \| attr<<8` | `-13`, `-1` |

`EPERM (-13)` is returned to any process that is not the console owner.

## Toolchain / linker notes

- `RUSTFLAGS` for this crate only: `-C target-cpu=x86-64 -C relocation-model=static -C code-model=large`.
  Never `target-cpu=native` (the T7400 is x86-64-v1 / SSSE3 ceiling).
- `user.ld` deliberately omits `PHDRS`: rust-lld folds declared PHDRs into
  one R|X load segment, which would fault on the mutable line buffer. It
  also lists rustc's `-C code-model=large` sections (`.ltext.*`,
  `.lrodata.*`, `.ldata.*`, `.lbss.*`) explicitly — orphan sections become
  extra PT_LOADs and the U1 loader refuses two loads on the same 4 KiB page.
  Result: 3 clean PT_LOADs (R|X, R, R|W) at +0x1000 / +0x3000 / +0x4000.
