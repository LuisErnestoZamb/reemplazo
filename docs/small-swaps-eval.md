# Small-swap fit-check: four direct-swap crate candidates

Evaluated 2026-11-21 on the pinned toolchain (**rustc 1.98.1 stable**, target
`x86_64-unknown-none` installed). All probes live in a scratch workspace
`/tmp/swap-probe` (repo untouched, no commits). Each candidate's real
crates.io source was downloaded via `cargo info` / the probe build and read
from `~/.cargo/registry/src/index.crates.io-*/`.

Security review for all four: `cargo audit` run over the probe workspace
lockfile (28 crate dependencies, RustSec advisory-db @1555 advisories) →
**exit 0, no advisories** for `uart_16550`, `pic8259`, `x86_64`,
`multiboot2` and their transitive deps.

| # | Candidate | Verdict |
|---|---|---|
| 1 | `uart_16550` → `kernel/src/serial.rs` | **SWAP** |
| 2 | `pic8259` → `kernel/src/pic.rs` | **KEEP-OURS** |
| 3 | `x86_64` → `kernel/src/idt.rs` (+`port.rs`) | **BLOCKED** |
| 4 | `multiboot2` → `bootinfo` | **SWAP** |

---

## 1. uart_16550 (rust-osdev) → `kernel/src/serial.rs` (99 lines)

**Version/license/maintenance:** `uart_16550` **0.9.0** released **2026-10-16**
(5 weeks ago; 0.5.0→0.9.0 all in 2026 — very active), **MIT OR Apache-2.0**,
MSRV 1.91.0 (≤ 1.98.1 ✓), repo `rust-osdev/uart_16550`. **RustSec: none** (audit exit 0).
**Features:** `default = []`, optional `embedded-io` — **there is no `nightly`
feature at all**. Category metadata explicitly `no-std`, `no-alloc`.
**Dependency tree (probe `cargo tree`):** `uart_16550 → bitflags` only — no
`x86_64` dep; its PIO backend carries its own `inb/outb` inline asm.

**Probe build (command + outcome):**

```
$ cargo check -p uart_probe --target x86_64-unknown-none   # in /tmp/swap-probe
    Checking uart_16550 v0.9.0
    Checking uart_probe v0.0.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 17.09s
```
The probe exercises every shim we need (const construction, `init(Config)`,
polled `try_send_byte`, blocking `send_bytes_exact`, `try_receive_byte`,
`fmt::Write` via `Uart16550Tty::from_inner`) — **PASS on stable, no nightly**.

**Answers to the specific questions:** polled TX **and** RX work on stable
`no_std` (`send_bytes_exact` spins on `LSR::THR_EMPTY`, same bit 5 we poll;
`try_receive_byte().ok()` is exactly our `Option<u8>` — `ByteReceiveError` is
a unit struct raised only when `DATA_READY` is clear). No `nightly` feature is
required. `core::fmt::Write` is **not** implemented on `Uart16550` itself; it
is implemented on the `Uart16550Tty` wrapper — and that wrapper's `write_str`
does the `\n → \r\n` translation we need (plus backspace echo on `8`/`0x7F`,
which we do *not* want in the log stream).

**API mapping (ours → theirs):**

| Ours (`serial.rs`) | uart_16550 0.9.0 |
|---|---|
| `SerialPort::COM1` (ZST value) | `const fn com1() -> Uart16550<PioBackend>` via `unsafe { Uart16550::new_port(0x3F8) }` (const, compile-time infallible for 0x3F8) |
| `init()`: IER=0, 8N1, FIFO 0xC7, divisor 3 | `init(Config { baud_rate: BaudRate::from_integer(38400), ..Config::DEFAULT })` → `Result<(), InitError>`; `Config::DEFAULT` is already IER=empty, 8N1, FIFO trigger 14 (= our 0xC7); `from_integer(38400)` yields divisor 3 at the crate's 1.8432 MHz clock const (our exact baud) |
| `write_byte` spins LSR bit 5, writes THR | `send_bytes_exact(&[b])` (spins `THR_EMPTY` internally) or loop `try_send_byte` + `spin_loop()` |
| `read_byte() -> Option<u8>` (LSR bit 0) | `try_receive_byte().ok()` — identical semantics |
| `impl fmt::Write` with `\n→CRLF` | **keep our own ~10-line impl** over `send_bytes_exact` (byte-identical output); `Uart16550Tty::write_str` also does CRLF but echoes backspace |
| `serial_print!` macro + `guard::check()` | **stays ours** (only its port-construction line changes) |
| fallible nothing (init is infallible) | `init()` can return `DeviceNotPresent` — ignore with `let _ =` (never halt: a dead UART must not stop the panic path) |

**Verdict: SWAP.** Reason: the known crate supports every need we have
(polled TX/RX on stable no_std, no nightly, exact baud/FIFO parity) and adds
what ours lacks (LSR line-error capture, config validation, upstream test
suite, an optional loopback self-test for a future boot check), with a
one-crate dependency (`bitflags`) and active maintenance. Per AGENTS.md the
"write from scratch" exception does not apply — the crate covers our needs.

### Implementation note (ordered; keeps `cargo xtask check` green at each step)

1. `kernel/Cargo.toml`: add `uart_16550 = "0.9"` (default features are empty;
   nothing to disable). `cargo xtask check` → green (dep compiles for
   `x86_64-unknown-none`, probe-verified; clippy only lints local crates).
2. Rewrite **only** `kernel/src/serial.rs` behind the existing facade so no
   call site changes:
   - Keep `#[macro_export] serial_print!/serial_println!` verbatim except the
     `SerialPort::COM1` construction line (the `guard::check()` stack-guard
     stays first, unchanged).
   - Keep a ZST `SerialPort { COM1 }` whose `init(self)` / `read_byte(self)`
     delegate to the crate (fresh `com1()` per call — deliberately *no* shared
     `static` state: a print from the IRQ handler must never alias a `&mut`
     held by mainline; per-call construction keeps today's reentrancy-safe
     behavior).
   - `impl fmt::Write for SerialPort`: loop bytes, `\n` → `send_bytes_exact(b"\r")`
     + byte — byte-identical to today's output (no Tty backspace echo).
   - SAFETY comments: one for `new_port` (COM1 register range, single-core,
     polled), same wording style as today's `outb` contracts.
   - Call sites **untouched**: `main.rs:49,177,329`, `shell.rs:42`,
     `guard::check()` in `main.rs:177`.
3. `cargo xtask check` (fmt + clippy `-D warnings` for host *and* kernel
   target + host tests + kernel cross-build) → must be green.
4. `cargo xtask smoke`: must still emit `BOOT_OK → MEM_OK → RTC_OK → PCI_OK →
   E1000_OK → NET_OK → PING_OK → DHCP_OK → DNS_OK → TCP_OK → TLS_OK → HTTP_OK
   → INT_OK → SHELL_OK` in order. This is the real proof: every marker is a
   `serial_println!`, and `SHELL_OK` + echo prove the `read_byte` RX path —
   i.e. that `init()` programmed the UART the way QEMU/GRUB expect. Not
   verified by this eval: runtime behavior (compile/link + API mapping only).

---

## 2. pic8259 (rust-osdev) → `kernel/src/pic.rs` (50 lines)

**Version/license/maintenance:** `pic8259` **0.11.0** released **2024-03-11**
(≈2.7 years without a release — stable, unmoving hardware code),
**Apache-2.0/MIT**, repo `rust-osdev/pic8259`. **RustSec: none** (audit exit 0).
**Features:** `default = ["nightly"]`, `stable = []` — but both are
**vestigial no-ops in 0.11.0**: `grep -rn feature pic8259-0.11.0/src/` finds no
`cfg(feature …)` anywhere (the flags date from 0.10.2, "enable compilation on
stable Rust"). Probe confirms **both** feature sets compile on stable 1.98.1.
**Dependency tree (verified — yes, it pulls x86_64):**

```
pic8259 0.11.0 → x86_64 0.15.5 (default-features=false, features=["instructions"])
                → bit_field, bitflags, const_fn, rustversion, volatile
```

**Probe build (command + outcome):**

```
$ cargo check -p pic_probe -p pic_default_probe --target x86_64-unknown-none
    Checking pic8259 v0.11.0
    Checking pic_probe v0.0.0
    Checking pic_default_probe v0.0.0
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```
`pic_probe` compiles the full swap pattern: `static` + `UnsafeCell` +
`unsafe impl Sync`, `ChainedPics::new(0x20, 0x28)` in a const context,
`initialize()`, `write_masks(0xFE, 0xFF)`, `notify_end_of_interrupt(32 + irq)`.

**API mapping (ours → theirs):**

| Ours (`pic.rs`) | pic8259 0.11.0 |
|---|---|
| ports 0x20/0x21/0xA0/0xA1 | identical (hardcoded in `ChainedPics::new`) ✓ |
| `init()` remaps master→0x20, slave→0x28 | `ChainedPics::new(0x20, 0x28)` + `unsafe initialize()` — **same ICW1..ICW4 sequence, plus port-0x80 delay writes ours lacks** |
| `init()` masks: master 0xFE, slave 0xFF | ⚠ `initialize()` **saves and restores the pre-init masks** — it does *not* mask. Must add `unsafe write_masks(0xFE, 0xFF)` after it, or IRQ lines GRUB left unmasked fire before the PIT is armed |
| `eoi(irq: u8)` — IRQ number 0..=15 | `unsafe notify_end_of_interrupt(vector: u8)` — takes the **vector** (32..=47); shim: `notify_end_of_interrupt(32 + irq)`, keeping our IRQ-number contract so `idt.rs:181,185` don't change |
| stateless free functions | needs a `static ChainedPics` + `UnsafeCell` + `unsafe impl Sync` (~10 lines, same pattern as our `Idt`) |
| 1 `unsafe` block (our `outb`s) | **4 `unsafe` fns** to wrap with SAFETY comments: `new`, `initialize`, `write_masks`, `notify_end_of_interrupt` |

**Verdict: KEEP-OURS** — exception reason: the known crate does not give us a
net improvement over the 50 lines we already have. (1) Its `initialize()`
deliberately *restores* stale masks, so the one behavioral contract our
`init()` exists for ("mask everything but IRQ0") must be layered on anyway —
the crate does not support our init contract out of the box. (2) It converts a
stateless module into a `static` + 4 unsafe entry points, i.e. the *same*
SAFETY-comment burden we already carry, plus aliasing questions for a shared
`&mut`. (3) It drags `x86_64 0.15.5` + 4 crates into ring 0 solely to wrap
`Port<u8>` — 4 asm instructions our `port.rs` already implements and which
every other driver shares. Our `pic.rs` is already proven by
`cargo xtask smoke` (`INT_OK`: int3 delivery + 3 PIT ticks through the
remapped PIC). Revisit only if a real-hardware run shows ICW timing problems
(the crate's port-0x80 delays would then be the reason to swap).

---

## 3. x86_64 (rust-osdev) → `kernel/src/idt.rs` (197 lines) + `port.rs` (84 lines)

**Version/license/maintenance:** latest **stable 0.15.5** (2026-07-11);
**0.16.0-rc.0** pre-release (2026-09-24); **MIT/Apache-2.0**; very active;
**RustSec: none** (audit exit 0).

**Probe build — CRITICAL QUESTION answered (command + outcome):**

```
$ cargo check -p x64_abi_probe --target x86_64-unknown-none
error[E0658]: the extern "x86-interrupt" ABI is experimental and subject to change
  --> x64_abi_probe/src/lib.rs:8:12
   = note: see issue #40180
error[E0599]: the method `set_handler_fn` exists for struct
  `x86_64::structures::idt::Entry<HandlerFunc>`, but its trait bounds were not satisfied
   = note: `HandlerFunc` is `pub struct HandlerFunc(())` without the
           `abi_x86_interrupt` feature (crate idt.rs:727)
error: could not compile `x64_abi_probe` (lib) due to 2 previous errors
```

Registering an interrupt handler through the crate's idiomatic API
(`set_handler_fn` + an `extern "x86-interrupt" fn`) **requires nightly**
(`#![feature(abi_x86_interrupt)]`). On stable 1.98.1 it fails twice: the ABI
itself (E0658) and, without the crate feature, the handler fn *type* is a unit
struct so `set_handler_fn` doesn't even exist (E0599). A nightly toolchain is
not installed here, and switching the pinned stable toolchain is out of scope
— this is the (a) toolchain-constraint blocker.

**Second finding (matters for any future use):** `x86_64 0.15.5`'s *default*
features are `["nightly", "instructions"]` — building it with defaults on
stable fails:

```
error[E0554]: `#![feature]` may not be used on the stable release channel
  --> x86_64-0.15.5/src/lib.rs:10:5  (feature(abi_x86_interrupt))
+ E0407 errors from the step_trait impls
```
Any future dependency must be declared
`x86_64 = { version = "0.15", default-features = false, features = ["instructions"] }`
(exactly what `pic8259` does). `0.16.0-rc.0` fixes `default = ["instructions"]`
but is a pre-release.

**Stable escape hatch (also probed):**

```
$ cargo check -p x64_probe --target x86_64-unknown-none
    Checking x64_probe v0.0.0
    Finished `dev` profile [unoptimized + debuginfo] target(s)
```
Without the ABI feature, `Entry::set_handler_addr(VirtAddr)` +
`InterruptDescriptorTable::load(&'static self)` + `instructions::port::Port`
all compile and work on stable. So a *partial* swap is technically possible —
but it is not a direct swap:

- `set_handler_addr` only replaces `IdtEntry` + our `lidt` asm (~120 of 197
  lines). `interrupts.S`, `isr_common`, `Frame` and `interrupt_dispatch` all
  stay ours — the crate contributes a descriptor table, nothing else.
- `Index<u8>` **panics for vectors < 32**, so the 31 exception entries must be
  set through named fields (`idt.breakpoint`, `idt.double_fault`, …) one by
  one, while 32..=255 go through `slice_mut` — *more* code than our uniform
  stub-table loop, plus the same `static` + `UnsafeCell` boilerplate we already
  have (crate `load()` needs `&'static self`).
- `Port<T>` could replace `port.rs` **bodies** while keeping the
  `unsafe fn inb/outb/inl/outl` signatures (zero call-site churn), or replace
  call sites in `rtc.rs`, `pit.rs`, `pci.rs`, `pic.rs`, `serial.rs` — either
  way it buys nothing: our 84 lines are 4 correct asm snippets shared by
  every driver.

**How the crate's stack-frame type would change our `Frame` contract:** the
crate's `InterruptStackFrame` is only `{rip, cs, rflags}` — exactly what the
CPU pushes — and with `extern "x86-interrupt"` handlers the compiler emits the
prologue/epilogue. A full swap would **delete `interrupts.S`'s `isr_common`,
our `#[repr(C)] Frame` (incl. the GPR snapshot kept for future context
switches/debugging), and `interrupt_dispatch`**, replacing 49 asm stubs with
per-vector nightly handler fns — a wholesale architectural change, not a
line-for-line swap. With `set_handler_addr` the `Frame` contract is untouched
(our stubs still push `[vector][error]` + GPRs).

**Verdict: BLOCKED** — exception (a) toolchain constraint: the API we would
need (registering handlers via `set_handler_fn` / `extern "x86-interrupt"`)
requires nightly on rustc 1.98.1 (E0658 proven by probe), and the pinned
stable baseline is a hard project rule. The stable `set_handler_addr` escape
hatch exists but only swaps the descriptor-table plumbing while keeping our
asm/dispatch architecture, at higher code cost and a 5-crate ring-0 dep — so
even the escape hatch is not worth taking. Revisit when (i) `x86_64` ≥ 0.16
goes stable with `default = ["instructions"]` *and* (ii) we decide to drop the
asm stubs for nightly-gated handlers (needs an explicit AGENTS.md toolchain
decision).

---

## 4. multiboot2 (phip1611 → rust-osdev/multiboot2) → `bootinfo` (405 lines, 13 tests)

**Version/license/maintenance:** `multiboot2` **0.28.0** released **2026-09-04**
(0.26.0 yanked → 0.26.1 → 0.27.0 → 0.28.0 within two weeks — very active;
repo is now `github.com/rust-osdev/multiboot2`, phip1611 is the maintainer),
**MIT/Apache-2.0**, MSRV 1.85.1 (≤ 1.98.1 ✓). **RustSec: none** (audit exit 0).
**Features:** `default = ["builder"]` → `alloc` (heap, for *building* MBI
structures — we never build). `alloc` is `#[cfg(feature = "builder")] extern
crate alloc;` in `lib.rs:53` — **the read path is alloc-free** (confirmed by
probe below; `multiboot2-common` docs: "Disable default features for
allocator-free" use).

**Probe build (commands + outcomes):**

```
$ cargo check -p mbi_probe --target x86_64-unknown-none      # default-features = false
    Finished `dev` profile [unoptimized + debuginfo] target(s)

$ cargo build -p mbi_probe --target x86_64-unknown-none --bin link_probe
    Finished `dev` profile ... (ELF 64-bit LSB pie executable, static-pie linked)
$ nm target/x86_64-unknown-none/debug/link_probe | grep -c "rust_alloc\|__alloc"
0
```
The link probe is a `#![no_std] #![no_main]` **binary** with a
`#[panic_handler]` and **no `#[global_allocator]`** that parses an MBI blob
through `BootInformation::load` and touches all five accessors we use — it
links clean with **zero allocator symbols**. If the read path needed `alloc`,
this fails at link/codegen ("no global memory allocator found"). **→ no_std
without alloc: PROVEN.**

```
$ cargo test -p mbi_probe --lib        # host, std available
running 5 tests
test tests::well_formed_blob_maps_our_api ... ok
test tests::null_and_misaligned_rejected ... ok
test tests::tag_size_below_header_rejected ... ok
test tests::missing_end_tag_rejected ... ok
test tests::tag_size_crossing_boundary_rejected ... ok
test result: ok. 5 passed; 0 failed
```

**Bounds validation (GRUB data is untrusted):** `BootInformation::load(ptr)`
is `unsafe` and checks null → 8-byte alignment → header size → walks
`validate_tag_sequence` *within the declared `total_size`*: tag header ≥ 8,
`size ≥ 8`, checked 8-alignment padding (`checked_add` overflow → error),
short-buffer → error, mandatory end tag. That tag-walk rigor is **equal to
ours** (our `parse` does the same walk with the same checks).

**The one real difference:** the crate takes a *pointer*, not a slice — it has
no buffer length, so it **cannot** check `total_size ≤ actual buffer`; the
caller contract is "`ptr` must be valid for reading the complete reported
size". Our `read_mbi` range pre-checks (`addr ∈ (0, 4 GiB]`, `total ∈ 8..=1 MiB`
(`MBI_MAX_BYTES`), `addr+total ≤ 4 GiB`, both before any slice/pointer is
built) therefore **stay in our code** and become the SAFETY contract for
`unsafe { BootInformation::load(ptr) }`. Consequence to document: a corrupt
`total_size` that is still ≤ 1 MiB and contains a valid end tag is *accepted*
by the crate where our parser rejected `total > len` — reads stay inside the
pre-validated in-map range (no safety issue); `total_size()` may then
over-reserve ≤ 1 MiB of frames (bounded, acceptable; note in `read_mbi`).

**API mapping (ours → theirs):**

| Ours (`bootinfo`) | multiboot2 0.28.0 |
|---|---|
| `BootInfo::parse(&[u8]) -> Result<_, ParseError>` | `unsafe { BootInformation::load(*const BootInformationHeader) } -> Result<_, LoadError>` (after our unchanged range pre-checks) |
| `bootloader_name() -> Option<&str>` | `boot_loader_name_tag().and_then(\|t\| t.name().ok()) -> Option<&str>` (type 2) |
| `basic_memory_kb() -> Option<(u32,u32)>` | `basic_memory_info_tag()` → `.memory_lower()` / `.memory_upper()` (type 4) |
| `memory_map() -> Option<MemoryMap>` (iterator) | `memory_map_tag() -> Option<&MemoryMapTag>` → `.memory_areas() -> &[MemoryArea]` (slice, zero-copy) |
| `region.base / region.length` | `area.start_address() / area.size()` |
| `region.is_available()` (`kind == 1`) | `area.typ() == MemoryAreaType::Available` (same value 1) |
| `framebuffer() -> Option<Framebuffer>` | `framebuffer_tag() -> Option<Result<&FramebufferTag, UnknownFramebufferType>>` → `.address()/.pitch()/.width()/.height()/.bpp()`, `kind` u8 ← map `buffer_type()` enum (0/1/2) |
| `total_size() -> usize` | `BootInformation::total_size() -> usize` ✓ |
| `ParseError` (Debug, printed in `main.rs:66`) | `LoadError` (derive Debug via thiserror, `{:?}` still works) |

**Verdict: SWAP.** Reason: the probe proves the read path is `no_std` +
alloc-free on our target, tag-sequence validation is as strict as ours,
license/RustSec/maintenance are all clean, and it replaces405 hand-written
lines + 13 tests with a heavily upstream-tested parser (the `builder` feature —
the only `alloc` part — must stay off).

### Implementation note (ordered; keeps `cargo xtask check` green at each step)

1. `kernel/Cargo.toml`: add
   `multiboot2 = { version = "0.28", default-features = false }` —
   **default features pull `alloc`** (they enable `builder`); keep `bootinfo`
   for now. `cargo xtask check` → green (dep compiles, probe-verified).
2. `kernel/src/main.rs`:
   - `use multiboot2::{BootInformation, BootInformationHeader, LoadError};`
     replacing `use bootinfo::{BootInfo, ParseError};` (line 31).
   - `read_mbi` (lines 190–220): **keep every pre-check verbatim** (addr
     bounds, `8..=MBI_MAX_BYTES`, `addr+total ≤ 4 GiB`); then replace
     `slice::from_raw_parts` + `BootInfo::parse(bytes)` with
     `unsafe { BootInformation::load(addr as *const BootInformationHeader) }`
     — one new SAFETY comment stating: range pre-checked above, single-core
     boot, no concurrent mutation; the crate re-reads `total_size` and
     validates the tag walk within it.
   - `report_boot_info` (224–263): remap accessors per the table; keep the
     `serial_println!` line formats **byte-identical** (`mbi: bootloader …`,
     `mbi: memory lower=… upper=…`, `mbi: N mmap regions, M MiB available RAM`,
     `mbi: framebuffer …`, `mbi: total_size=…`, then `BOOT_OK`).
   - error print at line 66 keeps `{:?}` (works on `LoadError`).
3. `kernel/src/memory.rs`: `use multiboot2::BootInformation;`; `init`/`selftest`
   signatures `&BootInfo` → `&BootInformation`; `info.memory_map()` →
   `info.memory_map_tag().map(|t| t.memory_areas())` iterating
   `area.typ() == MemoryAreaType::Available` with `start_address()`/`size()`
   (lines 44–61).
4. `cargo xtask check` → green (kernel clippy `-D warnings` covers the new
   call sites; the dep itself isn't linted).
5. `cargo xtask smoke` → must still assert `BOOT_OK → MEM_OK → … → SHELL_OK`
   in order within 30 s. The parse gate is proven by `BOOT_OK` itself (a
   rejected MBI halts with `FATAL: bad multiboot2 info` → marker missing) and
   `MEM_OK` proves the memory-map remap fed the frame allocator correctly.
6. **Port the adversarial tests, then delete `bootinfo`:** move the
   within-bounds hostile cases (null, misaligned, `size < 8`, tag crossing the
   declared boundary, missing end tag — all safe through the crate's pointer
   API when the test owns ≥ declared bytes) to a host test target; the old
   `rejects_declared_total_larger_than_buffer` case has **no equivalent**
   through a pointer API (the crate cannot know the buffer length) — keep it
   as a documented contract comment in `read_mbi` pointing at `MBI_MAX_BYTES`.
   Then: remove `bootinfo` from root `Cargo.toml` `members` + `default-members`
   and from `kernel/Cargo.toml`, delete `bootinfo/`, and update the two
   hardcoded package lists in `xtask/src/main.rs` (`clippy … -p bootinfo …`
   line 81 and `cargo test … -p bootinfo …` line 113) — otherwise
   `cargo xtask check` fails on the missing package. Run the full gate +
   smoke again before committing.

---

## What this eval did NOT verify

- No kernel code was changed; all results are **compile/link probes in
  /tmp/swap-probe + host unit tests**, not QEMU/hardware runs. Runtime claims
  for verdicts 1 and 4 are predictions gated by `cargo xtask smoke` as spelled
  out in their implementation notes.
- Nightly behavior of `x86_64` was not built (no nightly toolchain installed;
  E0658 on stable is definitive for our pinned-toolchain question).
- RustSec coverage = advisory-db snapshot at eval date (1555 advisories),
  `cargo audit` exit 0 over the 28-crate probe graph.
