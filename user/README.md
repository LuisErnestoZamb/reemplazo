# `user/` — first userland process

`hello/` builds `user-hello`, an `ELF64` `ET_EXEC` program that prints
`hello from userland\n` through the kernel's syscall gate and exits.

## Contract with the rest of OS

| Item | Value | Owner |
| --- | --- | --- |
| Load region | `USER_BASE = 0x0000_0080_0000_0000` (512 GiB, PML4[1]) | architect (`m-arch`) |
| ELF entry `e_entry` | `USER_BASE + 0x1000` = `0x8000_0000_1000` | `user/hello/user.ld` |
| First PT_LOAD (`headers`, R) | `p_vaddr = USER_BASE` | lld + `user.ld` |
| Second PT_LOAD (`user`, RWX) | `p_vaddr = USER_BASE + 0x1000`, includes `_start` | `user/hello/user.ld` |
| Page size | 4096 (`-z max-page-size=0x1000`) | `user/hello/build.rs` |
| Syscall entry | `int $0x80`, DPL3 gate (IDT[0x80]) | `m-privilege` |
| Syscall numbers | 0 Write(fd,buf,len), 1 Exit(code), 2 Yield, 3 Time | `m-syscalls` |
| Syscall args | SysV `rdi`, `rsi`, `rdx`; return in `rax` | `m-syscalls` |
| Initial stack | kernel sets RSP before jumping to `e_entry` | `m-elf-loader` / `m-scheduler` |

The loader must use **p_vaddr from the program headers**, not a fixed
legacy address. Every PT_LOAD has `p_vaddr % 4096 == p_offset % 4096`, so
mapping is a flat file→frame copy plus a zero-fill of
`p_filesz..p_memsz`. There are **no relocations** (linked at final virtual
address via `-C relocation-model=static`).

## Build

```sh
cargo build -p user-hello --release --target x86_64-unknown-none
cargo xtask user   # builds + copies ELF to target/iso-root/boot/hello.elf
readelf -l target/x86_64-unknown-none/release/user-hello
```

The integrator adds `module2 /boot/hello.elf hello` to the GRUB config of
the **new `smoke-user` mode only**. The existing smoke ISOs must stay
byte-identical — `cargo xtask user` writes only into `target/iso-root/boot`,
never into the ISO or the GRUB config.

## `userlib` migration

`m-syscalls` owns `userlib` with the authoritative syscall constants. When
it is a workspace member, replace the four `pub const SYS_*` in
`user/hello/src/sys.rs` with imports from `userlib` and delete the local
definitions; `main.rs` and `start.S` do not change. Until then the numbers
above are the single source of truth for this crate.

## Risk to verify on real hardware

`int $0x80` from 64-bit mode can zero the upper halves of registers on
some CPU/gate combinations. The entry pointer here is `0x8000_0000_xxxx`
(non-zero upper 32 bits), so the `m-privilege` gate plus `m-syscalls`
handler must preserve full 64-bit `rdi`/`rsi`/`rdx`. Flag this to the
integrator when wiring `smoke-user`.
