# Userland syscall ABI (milestone 1 — cooperative)

Status: **designed and implemented in the `m-syscalls` worktree; pending
integration with `m-privilege` (gate/IDT) and `m-scheduler` (process VMAs).**

## 1. Mechanism — decision

`int 0x80`, **not** `syscall`/`sysret`. The architect's blueprint assigns the
privilege transition to `m-privilege`, which owns `entry.S`, `idt.rs` and
`interrupts.S`: GDT6 + TSS, the vector-128 stub and a DPL3 (`0xEE`) IDT gate.
A CPL3 `int $0x80` makes the CPU switch to the TSS kernel stack, push the
old SS/RSP/RFLAGS/CS/RIP, and land in `isr_common`, which saves the GPRs into
an `idt::Frame` exactly as for any other interrupt.

This module is therefore transport-agnostic: the only kernel entry point it
exposes to `m-privilege` is

```rust
// in idt::interrupt_dispatch, vector 128 arm:
let ret = crate::userland::syscall::dispatch(frame);
frame.rax = ret as u64;
```

`dispatch` also writes `frame.rax` itself, so either convention is correct.
`isr_common` restores all GPRs and `iretq` returns to CPL3; no extra return
stub is needed. The kernel stack switch for CPL3 interrupts is provided by
`m-privilege`'s TSS, so no `swapgs` or ad-hoc stack juggling lives here.

**File boundaries respected by this milestone:** `entry.S`, `idt.rs` and
`interrupts.S` were not touched. `kernel/src/main.rs` received exactly one
line, `mod userland;`, so the new module is compiled; no init call or marker
print was added there. The marker hook is documented in §6.

## 2. Register convention and return values

| Item | Convention |
| --- | --- |
| Selector | `int $0x80`, IDT vector 128, DPL 3 |
| Number | `rax` on entry (read from `frame.rax`) |
| Args | SysV: `rdi, rsi, rdx, r10, r8, r9` → `frame.rdi…frame.r9` |
| Result | `i64` in `rax` (`frame.rax` also written by `dispatch`) |
| Errors | negative errno, never an exception into user space |
| Preserved | all other registers by `isr_common` |

## 3. Syscall table (stable numbers)

| # | Name | Args | Success | Failure |
| --- | --- | --- | --- | --- |
| 0 | `write` | `fd: u64, buf: *const u8, len: u64` | bytes written (`len`) | `-1`, `-2` |
| 1 | `exit` | `code: i64` | never returns | — |
| 2 | `yield` | — | `0` | — |
| 3 | `time` | — | ms since boot (`u64` as `i64`) | — |
| other | — | — | — | `-38` (`ENOSYS`) |

- `write` sends the bytes through the kernel's existing `serial_print!` path
  (COM1 **and** the VGA text mirror). fd 1 and 2 are the same console; fd 0
  is input and is refused. Milestone 1 is text-only: a non-UTF-8 buffer gets
  `-1` rather than being reinterpreted.
- `exit` prints a one-line notice and calls the scheduler's termination hook
  if one was installed with `set_exit_hook`; with no process subsystem it
  halts (fail-closed). The hook returns `!` in spirit; if it ever returns,
  the kernel still halts.
- `yield` switches tasks in milestone 2 (`sched::yield_current`); the PIT
  tick becoming a preemptive context switch is milestone 2 (scheduler).
- `time` is `crate::clock::now_ms()` — the PIT-driven monotonic clock already
  used by smoltcp, so it is consistent with the network stack's deadlines.

Errno constants (mirrored in `userlib` and in
`kernel/src/userland/syscall.rs`):

| Value | Name |
| --- | --- |
| `-1` | `EINVAL` |
| `-2` | `EFAULT` |
| `-13` | `EPERM` |
| `-38` | `ENOSYS` |

`EPERM` is reserved for the process/subsystem checks that arrive with the
scheduler; it is not returned by the four milestone-1 calls. There is no
`EBADF` in the blueprint table, so an invalid fd maps to `EINVAL`.

## 4. User-pointer validation (`copy_from_user`)

`kernel/src/userland/userptr.rs` is the only place that may turn a user
address into a slice. `validated_slice(ptr, len)` checks, in this order,
before any dereference:

1. `len == 0` → empty slice, no access. `len > 64 KiB` → `-1` (`EINVAL`).
2. `ptr + len` must not overflow, and the whole range must lie inside the
   global user window. The default start is the blueprint constant
   `USER_BASE = 0x0000_0080_0000_0000` (**not** the older `0x40…` value);
   the default end is `USER_BASE + 1 GiB`. The loader can replace both via
   `set_bounds`.
3. The range must fit **entirely inside one** of the current process's two
   VMAs — `brk` or stack — published with `set_vm(Vm { brk_*, stack_* })`.
   A buffer straddling two VMAs, an unregistered process (the default), a
   null pointer and any kernel-space address all yield `-2` (`EFAULT`).
4. Only then is a **read-only** `&[u8]` created with `from_raw_parts` under a
   documented `// SAFETY:`. No `&mut` to user memory is ever produced, no
   `unwrap`/`expect` touches user data, and every failure is an errno return.

The scheduler must call `userptr::set_vm(...)` from the PCB's `brk`/stack
VMAs on every context switch. If it does not, every user pointer fails
closed. A user #PF/#GP is not recovered here: `m-privilege`'s exception path
kills the offending process (milestone 2).

## 5. `userlib` (new crate, `no_std`, zero dependencies)

`userlib/` builds for `x86_64-unknown-none` and links into the user ELF. It
exports the syscall numbers and errnos above plus `write_str`, `write`,
`exit`, `r#yield` (alias `yield_now`) and `time`. The raw `int 0x80` wrapper
is the crate's only `unsafe` code, isolated in a private `arch` module; the
crate root is `#![deny(unsafe_code)]` (`forbid` cannot be scoped to allow the
asm wrapper — this is the documented deviation).

`user/hello/src/sys.rs` can inline the same seven-line wrapper; it should
take the numbers from `userlib::NR_*` if it links the crate, or keep the
constants byte-for-byte identical to §3.

## 6. `SYSCALL_OK` gate and integration checklist

`userland::syscall::selftest()` runs the real `dispatch` path once against a
temporarily registered one-VMA test buffer, then checks:

- `write(1, buf, len) == len` (and `frame.rax == len`) — the byte count;
- a pointer outside all VMAs returns `EFAULT`;
- an unknown number returns `ENOSYS`.

On success it prints `SYSCALL_OK`; on any mismatch it prints `FATAL: syscall:`
and halts, so a broken ABI cannot pass silently. The first real `dispatch`
also triggers it lazily, so a real process exercises the gate even if nobody
calls `selftest()` explicitly.

To land the marker in the smoke chain **after `SHELL_OK`**, the integrator
(owner of `shell.rs` and `xtask/`) must:

1. call `crate::userland::syscall::selftest();` in `shell::run` immediately
   after the `serial_println!("SHELL_OK")` line, and
2. append `"SYSCALL_OK"` to the xtask `MARKERS` array between `SHELL_OK` and
   `KEYBOARD_OK`.

The existing 30 markers are untouched by this crate; without those two
integration lines the smoke still runs 30/30 and simply does not look for
the new marker.

## 7. What remains (not in this milestone)

| Deliverable | State | What's left |
| --- | --- | --- |
| Syscall ABI + userptr + userlib | implemented here | review/merge with `m-privilege` |
| `int 0x80` gate + GDT6/TSS + stub | `m-privilege` | wire vector 128 to `dispatch` |
| `SYSCALL_OK` after `SHELL_OK` | ready (`selftest()`) | 1 line in `shell.rs` + 1 entry in xtask markers |
| First ELF 'hello' | `m-userland-elf` / `m-elf-loader` | load, map user pages in `0x80…`, register VMA, run |
| Process lifecycle | `m-scheduler` | `set_exit_hook`, `set_vm` on switch, kill on #PF/#GP |
| Preemptive tick | **done (hito 2)** | RR con quantum de 10 ticks, `fxsave`/`fxrstor`, #PF/#GP de CPL3 → kill; `SCHED_RR_OK`, `USER_YIELD_OK`, `USER_FAULT_OK` |
| Binary fds / larger I/O | deferred | UTF-8-only text console, 64 KiB cap |
