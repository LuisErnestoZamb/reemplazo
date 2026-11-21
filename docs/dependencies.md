# Dependency evaluation — HTTP / JSON / HTML parsing + heap milestone

**Date:** 2026-11-21 · **Policy:** use well-known, battle-tested crates; from-scratch only under exception
**(a)** the known crate doesn't support what we need, or **(b)** a from-scratch version offers a
worthwhile memory/CPU/RAM win on the target.

**Target constraints this evaluation is measured against** (see `AGENTS.md`): kernel is
`x86_64-unknown-none`, **`no_std` with no allocator yet** (verified: no `extern crate alloc`,
no `#[global_allocator]` anywhere in the workspace), x86-64-v1 baseline only (no SSE4.2+/AVX),
2.9 GB RAM, toolchain pinned to 1.98.1 (`rust-toolchain.toml`). Host-side crates (xtask) run on the
dev Mac and are unconstrained.

## How this was verified

- `cargo info <crate>` + the crates.io JSON API (versions, licenses, MSRV, dependency edges, reverse
  dependency counts) — queried 2026-11-21.
- Crate sources downloaded from the registry and inspected directly (`#![no_std]` attributes,
  `use std::` occurrences, `unsafe` counts, feature gating).
- **Scratch cross-builds** (no workspace changes): throwaway crates in the session temp dir built
  with `cargo build --target x86_64-unknown-none` — results per candidate below.
- `cargo tree -p <crate> --target x86_64-unknown-none` for exact dependency counts.
- **RustSec:** local clone of <https://rustsec.org/advisories/> (`~/.cargo/advisory-db`, commit
  `f291af9`, 2026-11-20, 1555 advisories) grepped per crate; additionally `cargo audit` was run
  read-only against the workspace `Cargo.lock` (77 crates) → **clean, exit 0, no vulnerabilities**.
  `cargo audit` only sees workspace deps, so every candidate crate was checked against the same
  advisory DB directly.
- Repo activity: GitHub API `pushed_at` / stars, queried 2026-11-21.

---

## Decision table

| Need | Candidate | Fits today (no heap)? | no_std | Needs `alloc`? | License | Latest release / repo activity | RustSec | Runtime deps (target tree) | Evidence |
|---|---|---|---|---|---|---|---|---|---|
| HTTP/1.1 parsing | **httparse** | ✅ **yes — verified cross-build + parses** | ✅ `default-features = false` | ❌ zero-copy into caller slices | MIT OR Apache-2.0 | 1.10.1 (2025-03-03); repo pushed 2026-06-30, ★718, 667 revdeps | none | **0** | [crates.io](https://crates.io/crates/httparse) · [docs.rs](https://docs.rs/httparse) · [src `lib.rs` `#![no_std]`](https://github.com/seanmonstar/httparse/blob/master/src/lib.rs) |
| JSON — fixed schema, pre-heap | **serde-json-core** | ✅ **yes — verified cross-build + nested parse** | ✅ `default-features = false` | ❌ (no `Value`, no dynamic structures) | MIT OR Apache-2.0 | 0.7.0 (2026-10-08); repo pushed 2026-10-08, ★199, 51 revdeps | none | 3 (`ryu`, `serde`, `serde_core`) + proc-macro chain | [crates.io](https://crates.io/crates/serde-json-core) · [docs.rs](https://docs.rs/serde-json-core) · [src `lib.rs`](https://github.com/rust-embedded-community/serde-json-core/blob/master/src/lib.rs) |
| JSON — arbitrary nesting (AI client) | **serde_json** (`default-features = false, features = ["alloc"]`) | ⛔ compiles, but needs heap at runtime | ✅ `#![no_std]` + `alloc` feature | ✅ **yes** | MIT OR Apache-2.0 | 1.0.154 (2026-10-11); repo pushed 2026-11-16, ★5676 | none | 4–5 (`itoa`, `memchr`, `serde_core`, `zmij`, +`serde`) | [crates.io](https://crates.io/crates/serde_json) · [docs.rs](https://docs.rs/serde_json) · [src `lib.rs` no-std section](https://github.com/serde-rs/json/blob/master/src/lib.rs) |
| JSON — lighter alternative (post-heap) | **miniserde** | ⛔ compiles, needs heap at runtime | ✅ `default-features = false` | ✅ **yes** (`Box`/`String` in visitor machinery + `Value`) | MIT OR Apache-2.0 | 0.1.46 (2026-07-18); repo pushed 2026-11-16, ★956, 73 revdeps | none | 3 (`itoa`, `zmij`, proc-macro `mini-internal`) | [crates.io](https://crates.io/crates/miniserde) · [docs.rs](https://docs.rs/miniserde) · [src `lib.rs`](https://github.com/dtolnay/miniserde/blob/master/src/lib.rs) |
| HTML — full parser (browser) | **html5ever** + markup5ever | ❌ **fails to build for `x86_64-unknown-none`** (needs `std`, not just `alloc`) | ❌ std-only | (needs `std` anyway) | MIT OR Apache-2.0 | 0.40.1 (2026-09-14); repo pushed 2026-11-17, ★2666, 443 revdeps | none | **19** (tendril, string_cache, parking_lot, phf, …) | [crates.io](https://crates.io/crates/html5ever) · [docs.rs](https://docs.rs/html5ever) · [src `lib.rs`](https://github.com/servo/html5ever/blob/main/html5ever/src/lib.rs) |
| HTML — active tokenizer, std-only | **html5gum** | ❌ fails to build for `x86_64-unknown-none` (std-only) | ❌ | (needs `std`) | MIT | 0.9.2 (2026-11-18); pushed 2026-11-18, ★175 | none | 0 by default | [crates.io](https://crates.io/crates/html5gum) · [docs.rs](https://docs.rs/html5gum) · [repo](https://github.com/untitaker/html5gum) |
| HTML — zero-alloc tokenizer today | **htmlparser** (jdrouet) | ✅ **verified cross-build** (tokenizer only, no tree) | ✅ `default-features = false` | ❌ | MIT OR Apache-2.0 | 0.2.1 (2024-11-03); pushed 2024-11-03, ★3 — **dormant** | none | **0** | [crates.io](https://crates.io/crates/htmlparser) · [docs.rs](https://docs.rs/htmlparser) · [repo](https://github.com/jdrouet/htmlparser) |
| HTML — std-only alternatives (checked, rejected) | `tl` 0.7.8 (2024-01-29, ★406, pushed 2024-08), `html5-parser` 0.4.2 (first release 2026-08, ★0, std-only), `html5tokenizer` 0.5.2 (2023, low usage) | ❌ std-only / too new / dormant | ❌ | — | MIT / MIT | see cells | none | — | [tl](https://crates.io/crates/tl) · [html5-parser](https://crates.io/crates/html5-parser) · [html5tokenizer](https://crates.io/crates/html5tokenizer) |
| Kernel heap (milestone) | **linked_list_allocator** | ✅ designed for exactly this | ✅ `#![no_std]` | — | Apache-2.0/MIT | 0.10.6 (2026-04-14); pushed 2026-04-14, ★243, 48 revdeps | [RUSTSEC-2022-0063](https://rustsec.org/advisories/RUSTSEC-2022-0063.html) **patched ≥0.10.2** (0.10.6 OK) | 1 (`spinning_top`) w/ default `use_spin` | [crates.io](https://crates.io/crates/linked_list_allocator) · [repo](https://github.com/rust-osdev/linked-list-allocator) |
| Kernel heap (alternative) | **talc** | ✅ | ✅ `#![cfg_attr(..., no_std)]` | — | MIT | 5.1.1 (2026-09-09); pushed 2026-09-09, ★573, 40 revdeps | none | 2 (`lock_api`, `scopeguard`) | [crates.io](https://crates.io/crates/talc) · [repo](https://github.com/SFBdragon/talc) |
| Kernel heap (alternative) | **buddy_system_allocator** | ✅ | ✅ `#![no_std]` | — | MIT | 0.13.0 (2026-03-30); pushed 2026-07-05, ★146 | none | 1 (`spin`) | [crates.io](https://crates.io/crates/buddy_system_allocator) · [repo](https://github.com/rcore-os/buddy_system_allocator) |

---

## 1. HTTP/1.1 parsing — **use `httparse` today**

**Recommendation: `httparse = { version = "1.10.1", default-features = false }` in the kernel/net
crate. Fits today, no heap required.**

Verification checklist:

- **`no_std`: yes.** `src/lib.rs` starts with
  `#![cfg_attr(not(any(test, feature = "std")), no_std)]`
  ([source](https://github.com/seanmonstar/httparse/blob/master/src/lib.rs)). Default feature is
  `std`, so **`default-features = false` is required** ([crates.io features](https://crates.io/crates/httparse)).
- **`alloc`: not needed.** Zero-copy by design: `Request::new(&mut headers)` / `Response::new(&mut
  headers)` write into a caller-provided `[Header; N]` array and borrow `&'buf str`/`&[u8]` out of the
  input buffer. No `Vec`, no `String`, no `Box` in the public path.
- **Runs in our kernel today: ✅ verified.** Scratch crate with `#![no_std]`, httparse
  `default-features = false`, built with `cargo build --target x86_64-unknown-none` → success.
- **x86-64-v1 safety (important given the `-C target-cpu=native` ban):** with `feature = "std"` off
  and no `target_feature = "sse4.2"/"avx2"`, `src/simd/mod.rs` compiles **only the SWAR path**
  (portable `u64` ops); the SSE4.2/AVX2 modules and the runtime `is_x86_feature_detected!` detector
  are `cfg`-ed out entirely
  ([`src/simd/mod.rs`](https://github.com/seanmonstar/httparse/blob/master/src/simd/mod.rs),
  [`src/simd/runtime.rs`](https://github.com/seanmonstar/httparse/blob/master/src/simd/runtime.rs)).
  No SSE4.2 instructions are emitted and no SIGILL risk on the T7400 (which lacks SSE4.2 anyway).
- **License:** MIT OR Apache-2.0 ([crates.io](https://crates.io/crates/httparse)).
- **Maintenance:** 1.10.1 released 2025-03-03; repo pushed 2026-06-30, ★718, 667 reverse
  dependencies (it underpins hyper and the wider HTTP ecosystem) — battle-tested by any measure.
- **RustSec:** no advisory for `httparse` in the advisory DB (checked 2026-11-20 clone).
- **Unsafe:** ~84 `unsafe` occurrences in `src/` (SIMD + iterator internals), but the crate
  `#![deny(clippy::undocumented_unsafe_blocks)]` requires a SAFETY comment on every one. On our
  configuration only the SWAR subset is compiled.
- **MSRV:** no `rust-version` field; CI's msrv job builds with **1.59.0**
  ([CI config](https://github.com/seanmonstar/httparse/blob/master/.github/workflows/ci.yml)) —
  far below our pinned 1.98.1.
- **Footprint:** 0 runtime dependencies (only dev-deps `criterion`, `rand`); ~3,079 code lines,
  45 KB crate ([crates.io](https://crates.io/crates/httparse)).

**Alternatives considered:** none better-known. `httparse` *is* the de-facto standard (667 revdeps);
writing an HTTP/1.1 parser from scratch would fail both policy exceptions — no memory win (it's
already zero-alloc) and no CPU win (SWAR/SIMD is the optimized path).

---

## 2. JSON parsing — two phases

### 2a. Today, no heap: **use `serde-json-core`** ✅

**Recommendation: `serde-json-core = { version = "0.7.0", default-features = false }` (+ your own
`serde = { version = "1", default-features = false, features = ["derive"] }`) for fixed-schema
protocol/config messages. Verified working today.**

Verification checklist:

- **`no_std`: yes.** `#![cfg_attr(not(feature = "std"), no_std)]`
  ([source](https://github.com/rust-embedded-community/serde-json-core/blob/master/src/lib.rs)).
  Default features are `["heapless"]`, so **`default-features = false`** drops `heapless` and gives
  a pure `no-std::no-alloc` build (the crate carries the crates.io
  [`no-std::no-alloc` category](https://crates.io/crates/serde-json-core)).
- **`alloc`: not needed.** `from_slice` parses into caller-owned types borrowing `&'a str` out of the
  input; serialization goes to `to_slice` (caller buffer). The dynamic `Value` type is explicitly
  listed as a "Non-feature" in the crate docs.
- **Runs in our kernel today: ✅ verified.** Scratch `#![no_std]` crate built for
  `x86_64-unknown-none` with `default-features = false`; runtime test passed for **nested structs +
  fixed-size arrays** (`{"id":"1","inner":{"x":7},"arr":[1,2]}`).
- **Known limitations (why this is *not* enough for the AI client):**
  1. **`deserialize_any` returns `Error::AnyIsUnsupported`** ([`src/de/mod.rs`](https://github.com/rust-embedded-community/serde-json-core/blob/master/src/de/mod.rs)) —
     you cannot parse a JSON document whose shape you don't know ahead of time. There is no
     `Value`/DOM. (It is *not* an event/SAX API either — it's serde-visitor-based pull
     deserialization into fixed Rust types; unknown *fields* can be skipped via
     `deserialize_ignored_any`, unknown *structure* cannot.)
  2. **String escapes:** `from_slice` (no buffer) passes escape sequences through **raw** — verified:
     `"a\nb"` decodes to the literal 4 chars `a\nb`. Correct unescaping requires
     `from_slice_escaped(&[u8], &mut [u8])` with a caller-provided buffer and an **owned**
     destination type (e.g. `heapless::String<N>`); feeding `&str` there fails with `CustomError`
     (verified). AI API payloads are full of `\n`/`\uXXXX`, so this matters.
  3. Fixed capacity: any owned string needs a statically chosen `N`.
- **License:** MIT OR Apache-2.0. **Maintenance:** 0.7.0 released 2026-10-08, repo pushed
  2026-10-08 (Embassy/rust-embedded-community, ★199, 51 revdeps) — actively maintained.
- **RustSec:** none for `serde-json-core`. Note its optional default `heapless` dependency has
  several *unsound* advisories —
  [RUSTSEC-2020-0145](https://rustsec.org/advisories/RUSTSEC-2020-0145.html) (patched ≥0.6.1) and
  [RUSTSEC-2026-0574](https://rustsec.org/advisories/RUSTSEC-2026-0574.html) + siblings
  0575–0582 (all patched ≥0.9.4). `0.7.0` requires `heapless ^0.9.2`, which resolves to **0.9.4 =
  patched**, and `default-features = false` avoids it entirely anyway.
- **Unsafe:** 8 occurrences (`from_utf8_unchecked`, unchecked push, buffer re-refs).
- **Footprint:** 3 runtime deps (`ryu`, `serde`, `serde_core`) + the `serde_derive` proc-macro
  chain at build time; ~2,778 code lines, 27 KB crate.
- **MSRV:** 1.87.0 (≤ our 1.98.1 ✅).

### 2b. AI client / arbitrary nesting: **heap milestone first, then `serde_json`**

**Recommendation: plan the heap milestone (§4) *before* the AI-client milestone and then use
`serde_json = { version = "1.0", default-features = false, features = ["alloc"] }`.**

Reasoning:

- Structured AI-API responses are *mostly* typed at the top level, but the payloads the AI client
  must handle include **arbitrary nesting**: tool-call `arguments`, structured-output blobs, unknown
  response variants. serde-json-core fundamentally cannot represent that (no `deserialize_any`, no
  `Value`) — a no-alloc event API is **not genuinely sufficient** for this milestone; it is
  sufficient for fixed-schema messages (status lines, simple configs, known endpoints) *before* the
  heap exists.
- `serde_json` is the industry-standard, battle-tested choice (★5,676, maintained by the serde
  org, released 2026-10-11, repo pushed 2026-11-16). Its own docs give the exact recipe
  ([`src/lib.rs` "No-std support"](https://github.com/serde-rs/json/blob/master/src/lib.rs)):
  `default-features = false, features = ["alloc"]` — **no `std` needed, only a global allocator.**
  Verified: scratch `#![no_std]` + `extern crate alloc` crate builds for `x86_64-unknown-none`.
- **Stack safety:** `serde_json` caps recursion at depth 128 by default (`remaining_depth: 128`,
  `src/de.rs`) — bounded stack use even on adversarial input, which matters in a kernel.
- **`miniserde`** is a credible lighter alternative if binary size/codegen time becomes a concern
  (no monomorphization — all deserialization via trait objects; *non-recursive by design*, so even
  `Drop` of a deeply nested `Value` can't overflow the stack; dtolnay-maintained, pushed
  2026-11-16). It also needs `alloc` (verified compiles, `extern crate alloc` in its `lib.rs`;
  `Box` in its visitor machinery). Trade-offs: JSON only, struct/unit-enum types only, **no
  deserialization error messages** (unit `Error`). Default recommendation stays **`serde_json`**;
  revisit miniserde under exception (b) only if measured code-size/CPU wins justify the API
  restrictions.
- **License/RustSec:** `serde_json`, `miniserde` — MIT OR Apache-2.0, **no advisories** in RustSec.

---

## 3. HTML parsing — **no suitable crate: from-scratch justified under exception (a)**

### What was verified

| Candidate | Result on `x86_64-unknown-none` | Notes |
|---|---|---|
| `html5ever` 0.40.1 | ❌ **`can't find crate for std`** (fails in `precomputed-hash`/`string_cache` and in html5ever itself) | **std-only, not merely alloc-needing.** `html5ever/src/lib.rs` has no `no_std` attr and uses `std::io::Write`, `std::collections::BTreeMap`, `std::cell::RefCell<Vec<...>>`; deps `markup5ever → tendril` (std), `web_atoms → string_cache → parking_lot` (std). No `no_std` feature flag exists (only `serde`, `trace_tokenizer`). Its SIMD fast path calls `is_x86_feature_detected!` (std). |
| `html5gum` 0.9.2 | ❌ std-only (`use std::` throughout) | Otherwise the most attractive base: WHATWG tokenizer, **`#![forbid(unsafe_code)]`**, 0 default deps, MIT, released 2026-11-18 (very active, ★175). README itself says it "does not generally qualify as a browser-grade HTML parser" (no tree construction by default). |
| `tl` 0.7.8 | ❌ std-only | MIT, ★406, but last release 2024-01, repo pushed 2024-08 — dormant; not spec-compliant by design. |
| `html5-parser` 0.4.2 | ❌ std-only (`use std::` in tokenizer/document) | Full tree construction + 1,726 html5lib tests passing, but **first release 2026-08-24, ★0** — brand-new, not battle-tested. |
| `html5tokenizer` 0.5.2 | ❌ std-only | Last release 2023, ~13 k downloads — marginal. |
| **`htmlparser` 0.2.1** | ✅ **builds & runs** | The only credible `no_std` option: **zero allocation, zero dependencies, `#![forbid(unsafe_code)]`** ([src](https://github.com/jdrouet/htmlparser/blob/master/src/lib.rs)), ~1.4 k LOC. **But:** it's an XML-subset pull *tokenizer* — no HTML5 tree construction, no tag-soup error recovery, limited DOCTYPE entity handling (README limitations). Real-world HTML (unclosed `<p>`, `<br>`, implied tags) is outside its model. Dormant: last release 2024-11-03, ★3. |

### Does the browser milestone require a DOM tree → heap regardless?

**Yes.** A browser-grade DOM is a mutable tree of nodes with parent/child/attribute storage —
`html5ever` itself implements it as `RefCell<Vec<Handle>>` open-element stacks etc.
([`tree_builder/mod.rs`](https://github.com/servo/html5ever/blob/main/html5ever/src/tree_builder/mod.rs)),
and a real DOM needs `Rc`-style shared ownership (or an arena). Either representation is dynamic
memory. A tokenizer alone *could* be zero-alloc (htmlparser proves it), but "browser" without a tree
is just text dumping. **The browser milestone therefore requires the heap milestone (§4) no matter
which parser is chosen.**

### Recommendation

1. **No suitable battle-tested crate exists for `no_std` HTML5 parsing** — the industry standard
   (`html5ever`, ★2,666, 443 revdeps) and the best-engineered alternative (`html5gum`) are both
   **std-only, verified by failed cross-build**. Under the new policy this is exactly
   **exception (a): the known crate doesn't support what we need (`no_std` + `x86_64-unknown-none`)**.
   → **from-scratch HTML5 tokenizer + tree builder is justified**, scheduled *after* the heap
   milestone (tree needs alloc; tokenizer alone could land earlier but has no consumer without the
   tree).
2. **Do not write it blind:** use `html5gum` (MIT, `forbid(unsafe_code)`, active, passes the
   html5lib tokenizer tests) and `html5ever`'s tree-construction rules as the **spec/reference
   implementations** to transcribe the WHATWG state machines from. A no_std *port/fork* of html5gum
   is legally allowed (MIT) and worth evaluating first — it would satisfy "battle-tested" better
   than greenfield — but a fork is a maintenance liability (upstream releases ~monthly); weigh that
   against exception (b) at milestone time. Decision: **port-first spike, fall back to from-scratch**.
3. **Pre-heap stopgap (only if something needs HTML before the heap):** `htmlparser` —
   `default-features = false`, zero deps, verified building — but treat it as a *tokenizer for
   well-formed markup only*, not a browser parser. If no early consumer exists, skip it entirely.
4. Rejected: `tl` (dormant, non-spec), `html5-parser` (2 months old, ★0), `html5tokenizer`
   (stale, marginal).

---

## 4. Heap allocator milestone

### Recommendation: **add a kernel heap BEFORE the browser and AI-client milestones**

Both milestones need `alloc`:

- **AI client:** `serde_json`'s `Value`/`Vec`/`String` (and miniserde's `Box`-based visitors)
  require a global allocator; serde-json-core cannot cover arbitrary nesting (§2b).
- **Browser:** DOM tree storage requires dynamic memory regardless of parser (§3).
- Also unblocks `alloc` collections for git (diff/patch buffers), ssh (key/blob parsing), the
  editor (rope/gap buffers), and any `String`-carrying shell output — all currently constrained to
  static buffers.
- It is a small, well-understood milestone: carve a region out of the existing bitmap frame
  allocator (`kernel/src/memory.rs`), register `#[global_allocator]`, add `extern crate alloc;`.
  Stable Rust, no nightly features needed on our pinned 1.98.1.

**Sequencing:** `… TLS_OK → HTTP_OK → INT_OK → SHELL_OK → HEAP_OK → (AI-client JSON, browser DOM)`.

### Allocator crate options (all `no_std`, all RustSec-clean, all currently maintained)

1. **`linked_list_allocator` 0.10.6 — recommended default.**
   [crates.io](https://crates.io/crates/linked_list_allocator) ·
   [repo](https://github.com/rust-osdev/linked-list-allocator) ·
   [docs.rs](https://docs.rs/linked_list_allocator)
   - The canonical choice for hobby/from-scratch x86 kernels (the phil-opp blog-OS allocator —
     linked in the crate homepage), `#![no_std]`, Apache-2.0/MIT, MSRV 1.61, last release
     2026-04-14 (★243, 48 revdeps).
   - **RustSec:** [RUSTSEC-2022-0063](https://rustsec.org/advisories/RUSTSEC-2022-0063.html)
     (out-of-bounds writes on tiny/unaligned heaps) is **patched in ≥0.10.2**; we'd take 0.10.6.
   - Default feature `use_spin` pulls `spinning_top → lock_api → scopeguard` (3 extra crates).
     In the kernel prefer `default-features = false` and wrap `Heap` in our own **interrupt-aware**
     lock (a plain spinlock that doesn't disable IRQs can deadlock against an allocation in an
     interrupt handler).
   - ~95 `unsafe` occurrences — expected for an allocator; SAFETY-commented upstream.
2. **`talc` 5.1.1 — performance alternative.**
   [crates.io](https://crates.io/crates/talc) · [repo](https://github.com/SFBdragon/talc)
   - MIT, MSRV 1.64, last release 2026-09-09 (★573, 40 revdeps), no RustSec advisories,
     `#![cfg_attr(not(any(test, feature = "error-scanning-std")), no_std)]`, `GlobalAlloc` impls
     with optional `lock_api` sync wrappers. Benchmarked as one of the fastest Rust allocators;
     ~82 `unsafe`. Choose it if profiling on the T7400 shows allocator overhead.
3. **`buddy_system_allocator` 0.13.0 — structure-matched alternative.**
   [crates.io](https://crates.io/crates/buddy_system_allocator) ·
   [repo](https://github.com/rcore-os/buddy_system_allocator)
   - MIT, `#![no_std]`, last release 2026-03-30 (★146), no RustSec, 1 dep (`spin`), ~39 `unsafe`.
     A buddy system maps naturally onto a frame allocator (allocate 2^k frames), which is how rCore
     does it — reasonable if we want heap granularity tied to physical frames.
   - (Also checked: **`rlsf`** 0.2.3, TLSF real-time allocator, MIT/Apache, MSRV 1.61, released
     2026-07-27, no advisories — a fine option if we later need allocation-latency guarantees.)

**Clarifications on the candidates named in the task:**

- **`rlibc` is not a heap allocator.** It's a crate of `memcpy`/`memset` shims, v1.0.0 from
  **2016** ([crates.io](https://crates.io/crates/rlibc)) and effectively obsolete — rustc's
  `compiler_builtins` already provides these for `no_std` targets. Do not add it.
- **`tls-allocator` does not exist on crates.io** (`cargo info tls-allocator` → not found). The TLSF
  option is **`rlsf`** (above) / `embedded-alloc`'s TLSF backend (embedded-oriented, less suitable
  for x86_64 than the three listed).

### Suggested milestone shape

- Region: e.g. 64–256 MB carved from the frame allocator at boot (2.9 GB RAM — cheap insurance,
  growable later via `Heap::extend`).
- Crate: `linked_list_allocator = { version = "0.10.6", default-features = false }`, wrapped in our
  own IRQ-safe lock → `#[global_allocator]`.
- Smoke test: extend the serial-marker chain with `HEAP_OK` (alloc/free/realloc round-trip, plus a
  `Vec`/`String` sanity check), following the existing `cargo xtask smoke` pattern
  (`… TLS_OK → HTTP_OK → INT_OK → SHELL_OK → HEAP_OK`).

---

## Summary of decisions

| Need | Decision |
|---|---|
| HTTP/1.1 parsing | **Use `httparse` today** (`default-features = false`) — no_std, zero-alloc, verified in-kernel, SWAR-only on our baseline, RustSec-clean. |
| JSON, pre-heap | **Use `serde-json-core` today** (`default-features = false`) for fixed-schema messages; mind the escape-buffer caveat. |
| JSON, AI client | **Heap milestone first → `serde_json` (`features = ["alloc"]`)**; arbitrary nesting is impossible without a heap; `miniserde` is the lighter runner-up. |
| HTML parsing | **No suitable `no_std` crate — from-scratch justified under exception (a)**; html5ever/html5gum verified std-only. Heap milestone required first (DOM); spike a no_std port of `html5gum` before greenfield. `htmlparser` only as a pre-heap tokenizer stopgap. |
| Heap allocator | **Add before browser/AI-client milestones.** Default: **`linked_list_allocator` 0.10.6** (advisory patched, `default-features = false` + own IRQ-safe lock); alternatives `talc` (speed) and `buddy_system_allocator` (frame-aligned). |
