# Research: the opencode-like AI client + VSCode-like editor

Date: 2026-11-21 · Status: **proposed** (awaiting milestone execution)
Scope: deliverable #4 of AGENTS.md — "an opencode-like AI client with a VSCode-like
editor". Answers three questions: which crates may we reuse (dependency policy
exceptions recorded), what does the architecture look like inside today's
kernel-only tree, and what is the milestone order with smoke-testable markers.

## 1. What the tree already has (from this checkout)

| Building block | Where | Relevance |
|---|---|---|
| Kernel heap (`linked_list_allocator`) + `Vec` proof (`ALLOC_OK`) | `kernel/src/heap.rs` | `alloc`-based crates are now admissible (serde_json needs it) |
| PS/2 keyboard → set-1 decode → `keyboard::next_char()` | `kernel/src/keyboard.rs` | raw character feed for an editor (no `LineDiscipline` in raw mode) |
| VGA text console + ANSI **swallowing** state machine | `kernel/src/vga.rs` | today escapes are *discarded* (the `clear` builtin must not paint `[2J[H`); a TUI needs them *interpreted* or, better, a direct cell API |
| Serial+VGA line discipline, minimal shell (`help`, `echo`, …) | `kernel/src/shell.rs` | apps enter from a shell builtin, exactly like `ai`/`edit` will |
| TLS 1.3 client, HTTP/1.1 **GET** + RFC 9112 framing (content-length / chunked / close-delimited) | `kernel/src/tls.rs`, `net/src/http.rs` | the HTTPS transport for the real API; **POST with a body does not exist yet** |
| smoltcp stack, DNS, plain-HTTP path, slirp constants (`SLIRP_GATEWAY` = 10.0.2.2) | `kernel/src/netstack.rs` | guest → host mock server for a secret-free smoke |
| **No `serde` anywhere** | `Cargo.lock` (grep `name = "serde"` → nothing) | JSON milestone starts from zero |

Everything today runs **in the kernel** (`kernel_main` → `shell::run`). There is no
userland/syscalls yet, so the client and editor start as kernel apps (module tree
`kernel/src/apps/`), with the explicit note that they move to userland when the
syscall milestone lands (documented here so nobody mistakes it for an accident).

## 2. JSON

| Candidate | no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|
| **`serde_json` 1.x + `serde`** | **yes — official**: `serde_json = { version = "1.0", default-features = false, features = ["alloc"] }` ("No-std support: as long as there is a memory allocator", [docs.rs/serde_json](https://docs.rs/serde_json)) | alloc (we have it) | De-facto standard, dtolnay, extremely active | none current (RUSTSEC-2021-0100 was serde 0.9 era) | MIT/Apache-2.0 | https://crates.io/crates/serde_json |
| `serde-json-core` | yes (guaranteed stable-Rust build, "no dynamic allocation") | **no** — fixed caller buffers | crates.io page shows modest activity | none | MIT/Apache-2.0 | https://crates.io/crates/serde-json-core |
| `miniserde` | partially (its own story) | alloc | niche | none | MIT/Apache-2.0 | https://crates.io/crates/miniserde |

**Decision: adopt `serde_json` + `serde` with `default-features = false, features =
["alloc", "derive"]`.** The earlier plan ("serde-json-core today / serde_json after
heap", docs/dependencies.md §JSON) had heap as its precondition — heap has landed
(`f82e61b`), so the precondition is met and we take the standard: derive types for
the request/response, `from_slice` on response bytes, `serde_json::to_vec` for the
request body. `serde-json-core` stays in the plan only as the fallback if a
host-test probe shows `serde_json` pulling something unacceptable into the kernel
ring-0 dependency set (checked with `cargo tree -p kernel` at integration; review
recorded in the commit, per the skill's dependency gate).

Derived structs (host-tested in a crate, see §6): `ChatRequest {model, messages,
stream, temperature?}`, `ChatResponse {choices[{message{content}}], …}`,
`StreamChunk {choices[{delta{content}?}]}`.

## 3. Transport: POST + SSE

| Need | Candidate | Fits no_std | Verdict |
|---|---|---|---|
| HTTP POST with a JSON body | extend our `net::http::build_request` (method + `Content-Type` + `Content-Length` + body) | — (it is ours) | **do it** — `ureq`/`reqwest`/`hyper` are all std-only; our GET path (with `tls_fetch`) already proved the pattern |
| SSE (`text/event-stream`) parsing | `eventsource-stream` (futures/std), `reqwest-eventsource` (std) | **no** | **from-scratch line parser — exception (a)**: every known SSE crate needs `futures`/`std`; the format is ~40 lines (`data: …` lines, blank-line event boundary, `data: [DONE]` terminator), same reasoning and adversarial-test bar as `git-pktline` |
| incremental body | our `ResponseParser::feed` already emits body bytes as they arrive; close-delimited framing is supported | — | reuse — SSE responses are close-delimited (`Connection: close`), which the framer handles today |

The response parser's per-response `reset()` (landed with the git milestone) is what
makes sequential exchanges safe; the AI client adds a third sequential exchange
pattern on top of it.

## 4. Rendering / TUI ("VSCode-like" chrome)

| Candidate | no_std | Notes | Source |
|---|---|---|---|
| **`ratatui` 0.30 / `ratatui-core` 0.1** | **yes — official**: `default-features = false` disables `crossterm`/`serde`/std backends; docs instruct a **custom `Backend`** for no_std targets ([ratatui.rs/concepts/no-std](https://ratatui.rs/concepts/no-std/)) | layout solver, `Block`/`Paragraph`/`List`/`Tabs`, double-buffered `Cell` grid — the entire "VSCode chrome" vocabulary; MIT; extremely active (commits within the last day at time of writing); huge ecosystem = battle-tested | https://crates.io/crates/ratatui |
| `crossterm` (ratatui's default backend) | no — termios/raw-mode/ANSI to a tty | N/A: our "tty" is `0xb8000`; we write the `Backend` | https://crates.io/crates/crossterm |
| hand-rolled widgets on our own cell buffer | — | fallback if the ratatui no_std probe fails | — |

**Decision: adopt `ratatui` (`default-features = false`, no backend feature) behind
a `VgaBackend` we write** — `Backend::draw` receives `(x, y, Cell)` items and we
diff them into the VGA text buffer (`kernel/src/vga.rs` gains a *cell API*:
`put_cell(x, y, ch, attr)`, `flush_diff`, cursor control — the ANSI *swallowing*
state machine stays for shell output; the TUI never goes through ANSI). This is a
**build-probe gate**: first act of the TUI milestone is `cargo check` of ratatui
for `x86_64-unknown-none` with a stub backend; if it drags in anything std the
fallback is the hand-rolled cell layer (the diff/flush code is needed either way).

Text mode is the deliberate scope: GRUB currently leaves a **text** framebuffer
(`sync_vga` requires `FramebufferType::Text` — "never on our chain" otherwise),
1280x800 panel notwithstanding. A graphical GUI (VBE linear framebuffer + font
atlas + retained widgets) is a separate future milestone (§7 A6) and would flip
`sync_vga` to RGB — not in scope here.

## 5. Editor buffer

| Candidate | no_std | Maintenance | Verdict |
|---|---|---|---|
| `ropey` 1.6.1 | **no — verified in source**: `use std::ops::Bound`, `impl std::error::Error`, `std::result::Result`, no `#![no_std]` ([source](https://docs.rs/crate/ropey/latest/source/src/lib.rs)) | active | **rejected: exception (a)** — the known rope cannot build for our target. Also ships a default `simd` feature (unnecessary surface given the SSSE3 ceiling) |
| `crop` (noib3) | std-ecosystem (helix line) | active | rejected: same exception (a), unverified |
| `sp-ropey` (Substrate fork) | yes | **abandoned ~5 years** (4.5k downloads total) | rejected: fails the battle-tested bar |
| **gap buffer over `Vec<u8>` + line index, from scratch** | yes | ours | **adopt — exceptions (a) and (b)**: no known maintained no_std rope exists, *and* for our actual workload (source files on a 120 GB/2.9 GB machine, bounded to a few MB per buffer) a flat buffer is less memory than a rope tree, simpler to make adversarially testable, and trivially `forbid(unsafe_code)` |

The buffer crate gets the usual adversarial host tests (UTF-8 boundary edits,
gap compaction, line-index consistency under random edit sequences vs a `Vec`
oracle). Syntax highlighting later = a small host-tested lexer per language
(Rust, JSON, markdown first) painting `Cell` styles — no crate needed.

## 6. Where the code lives

```
aiwire/            new workspace crate — chat API wire types (serde derive),
                   request builder, response/SSE parsers — HOST TESTED
kernel/src/apps/   mod apps; screen (cell diff), tui (ratatui VgaBackend),
                   editor (gap-buffer glue + viewport), ai (event loop, config)
kernel/src/…       shell builtin `ai` and `edit` enter/exit the apps
xtask/             `chat-mock`: tiny std TCP server serving a canned
                   OpenAI-style completion for the smoke (see §7)
```

Rationale mirrors `git-pktline` (pure codec → host-tested crate, transport glue →
kernel): everything with wire/user input must be testable on the host.

**API shape (default, swappable): OpenAI-compatible `POST /v1/chat/completions`.**
It is the de-facto dialect — llama.cpp server, vLLM, LM Studio, OpenRouter and
most proxies speak it, which also means a *local* model server is a first-class
target for this 2007 machine (no cloud needed to demo). Alternatives considered:
Anthropic `/v1/messages` (narrower ecosystem), opencode's own protocol (no stable
public server API). Config = `endpoint`, `model`, optional `key`; **secrets live
in RAM only** — typed at runtime, never in the repo, never in serial/VGA logs
(the log-injection sanitizing used by `git.rs` applies to rendered model output
too). Persistence of config waits for the filesystem milestone (installer/fatfs).

## 7. Milestone plan

| # | Milestone | Build first / smoke marker | Depends on |
|---|---|---|---|
| A1 | Screen layer: cell API + diff flush into `vga.rs`, ratatui no_std **build probe**, `VgaBackend`, first full-screen frame (status bar + list) driven by raw keyboard | **`TUI_OK`** (frame rendered + navigable in QEMU) | ratatui probe |
| A2 | Editor: `editorbuf` gap-buffer crate (host tests) + viewport/cursor/editing keys/line numbers/in-memory buffers; save/open deferred to the FS milestone | **`EDITOR_OK`** (edit a buffer, undo/redo proof, on-screen) | A1 |
| A3 | AI chat over the **mock**: `aiwire` crate (serde_json request/response/SSE, host tests) + `net::http` POST + xtask `chat-mock` on 127.0.0.1, guest reaches it at `10.0.2.2:<port>` (slirp, no DNS, no secrets) → render the reply in a chat pane | **`AI_CHAT_OK`** (request built → mock 200 → JSON parsed → reply rendered) | A1, serde_json, POST, SSE |
| A4 | Real endpoint over TLS 1.3 + streaming SSE + key entry (RAM) — **manual verification** with the user's key/endpoint; smoke keeps the mock | manual run (documented in the doc + AGENTS note); not a smoke marker (no secrets in CI) | A3, TLS |
| A5 | Editor ↔ chat integration: `ai` pane can quote the buffer, apply a completion into the editor (the "opencode-like" workflow) | **`AI_EDIT_OK`** — **landed 2026-11-21**: mock completion applied into the retained editor buffer (undo/redo round-trip asserted on the buffer, frame read back from `0xb8000`) + interactive `ai apply` | A2, A3 |
| A6 | Future: graphical GUI on the VBE framebuffer (font atlas, retained widgets) and/or userland relocation of `apps/` behind syscalls | separate research | A1–A5 |

Order rationale: A1 before anything because both apps render; A3 before A4 because
the mock makes the whole chain smoke-testable **without credentials**, keeping the
30 s boot-smoke budget honest; A5 is the actual product moment.

## 8. Risks / open questions

- **ratatui no_std probe — resolved in A1 (2026-11-21):** cross check
  of `ratatui 0.30.2` for `x86_64-unknown-none` with
  `default-features = false` passes clean (see the appendix); the
  hand-rolled widget fallback was not needed. Residual risk is runtime,
  not build: `Terminal`'s two internal buffers are heap (`alloc`),
  bounded at 2 × cols × rows ratatui cells per session.
- **Boot-smoke budget**: A3 adds a host-side mock server to xtask (must be killed
  on failure — the existing `stop_vm`/orphan-watch discipline applies to it too).
- **Bounded memory**: response bodies and editor buffers get explicit byte caps
  (`READ_CAP`-style) — a hostile/absurd API reply must not exhaust the heap.
- **Model output is untrusted**: rendered through the sanitizing path (printable
  ASCII/CRLF policy decided per pane; UTF-8 display is a later refinement).
- **No FS yet**: editor cannot save; chat cannot persist history. Both are listed
  as explicitly deferred, not forgotten (they land with the installer's FS work).

## Appendix: verification log

- 2026-11-21 — `serde_json` no_std+alloc confirmed from docs.rs ("No-std
  support" section) and serde.rs/no-std.html.
- 2026-11-21 — `ropey` 1.6.1 std-only confirmed from its published `src/lib.rs`
  (`std::ops::Bound`, `impl std::error::Error`).
- 2026-11-21 — ratatui no_std confirmed from the official
  `ratatui.rs/concepts/no-std/` page (0.30, `default-features = false`, custom
  `Backend`, `ratatui-core` alternative).
- 2026-11-21 — **A1 build probe run:** `ratatui 0.30.2` (+ `ratatui-core
  0.1.2`, `ratatui-widgets 0.3.2`) cross-checks clean for
  `x86_64-unknown-none` as a kernel dependency with `default-features =
  false`; all three crates are `#![no_std]` + `alloc`, no `crossterm`/`std`/
  `serde` feature is compiled, `cargo audit` clean (0 advisories, 129
  crates). Adopted: `VgaBackend` + widgets are the A1 rendering path.
- 2026-11-21 — no_std SSE crate search: only futures/std-based options found
  (`eventsource-stream`, `reqwest-eventsource`).
- 2026-11-21 — **A5 landed (`AI_EDIT_OK`, markers 22 → 23):** the editor's
  buffer became a **retained document** — one `static mut Option<Doc>`
  (buffer + caret) in `apps/editor.rs` under the repo's single-consumer idiom
  (boot proof before `shell::run`, `edit`/`ai apply` served sequentially, IRQ0
  never touches it). `edit` mounts it (`Esc` saves back instead of dropping;
  the in-memory sample on first use), `ai apply` quotes its cursor line → one
  sanitized mock exchange shared by all three callers
  (`apps::ai::one_shot`: `ai <message>`, `ai apply`, the boot proof) →
  `apply_completion` inserts at the cursor through the same `insert_at`
  primitive typing uses, so the completion is **one undo entry** (Tab removes
  it, Delete restores it). Boot proof: seed → quote → exchange → apply →
  undo/redo round-trip asserted byte-exact on the buffer → editor frame read
  back from `0xb8000`. Verified: `cargo xtask check` exit 0; `cargo xtask
  smoke` PASS 23/23 with `AI_EDIT_OK` between `AI_CHAT_OK` and `SHELL_OK` (all
  22 pre-existing markers intact); manual HMP session against `cargo xtask
  run` — first `edit` showed the proof's document (`… // TODO: ask AI
  reemplazo: mock reply ok`, `Ln 3,Col 61 [+]`), caret moved to line 4 +
  Esc, `ai apply` printed `ai: applied \`reemplazo: mock reply ok\` at the
  editor cursor`, reopening `edit` showed `} reemplazo: mock reply ok`
  (`Ln 4,Col 27 [+]`), Tab removed it, Delete restored it; `ai hello` still
  prints the mock reply (A3 path unchanged).
