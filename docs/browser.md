# Research: the browser

Date: 2026-11-21 · Status: **proposed** (awaiting milestone execution)
Scope: deliverable #5 of AGENTS.md — "a browser". Answers: what can we reuse,
what must be written from scratch (dependency-policy exceptions recorded), what
is honestly in scope for a 2007 laptop with a text console today, and the
milestone order with smoke markers.

## 1. Scope decision — a text-mode browser first

The deliverable is "a browser", not "a browser engine". The honest scope for
this hardware and tree:

| In scope (v1) | Out of scope (recorded, not forgotten) |
|---|---|
| URLs, HTTP(S) fetch, redirects | **JavaScript** — every maintained Rust JS engine (boa, quickjs-rs bindings) is std-only and enormous; a no-std engine is a project of its own. v1 targets pages that work without JS (docs, wikis, raw file views, API responses) |
| HTML parsing → tree → **text rendering** in the TUI screen layer (Lynx/w3m class, but with our own layout) | **GUI rendering** — shares milestone A6 of docs/ai-client.md (VBE framebuffer + font atlas); a Lynx-class v1 still exercises the whole network+parse+layout stack |
| CSS **subset** (display, colors→attributes, font-weight/style, lists, margins in cells) | full cascade/specificity edge cases, flex/grid, `@media`, external stylesheets beyond GET+parse |
| Link navigation (keyboard), history back/forward, status bar | cookies jar, auth, forms beyond GET query, images (need decoders + GUI), HTTP cache |

Rendering target: the **same TUI screen layer as the AI client** (milestone A1
of docs/ai-client.md) — the browser is a second consumer of it, which is
precisely why A1 must land first.

## 2. What the tree already has

- `html` crate: **zero-copy HTML5 tokenizer** (1737 lines, 47 adversarial
  tests) — landed with the html milestone; the html5gum no_std spike that
  justified writing it is recorded in its module docs.
- HTTPS client (`tls.rs` + `net::http` GET, RFC 9112 framing, redirect-less),
  DNS, smoltcp — everything a fetch needs except **URL handling, redirects and
  POST** (POST is AI-client milestone A3's addition; the browser only needs GET).
- Heap (`alloc`), keyboard, VGA text console, and (planned) the A1 screen layer.

## 3. URL handling

| Candidate | no_std | Notes | Source |
|---|---|---|---|
| **`url` (servo/rust-url)** | **yes — official**: "The `alloc` feature provides no_std support" ([docs.rs/url](https://docs.rs/url)); release notes track no-std work | WHATWG-compliant, the de-facto standard; deps: `idna` (unicode tables), `percent-encoding`, `form_urlencoded` | https://crates.io/crates/url |
| `fluent-uri`, `uriparse`, `iri` | mixed, smaller | less battle-tested than servo's | — |
| from-scratch RFC 3986 parser | — | fallback | — |

**Decision: adopt `url` with `default-features = false, features = ["alloc"]`,
gated by a build probe** (`cargo check --target x86_64-unknown-none`, same
discipline as the ratatui probe). Rationale: URL parsing looks trivial until
relative-resolution, percent-encoding and IDNA edge cases appear; servo's
implementation is battle-tested (exception-(a)-free path). Fallback if the
probe fails: a bounded RFC 3986 subset (scheme/authority/path/query/fragment +
relative resolution) from scratch, recorded as exception (a) in the commit.

## 4. HTML: tokenizer ✓ → tree construction

There is **no maintained no_std HTML tree builder**: `html5ever`+`markup5ever`
are std (servo), `html5gum` cannot build no_std (proven by our own spike,
recorded in `html/src/lib.rs`), and the tokenizer-only crates don't build trees.

**Decision: from-scratch tree construction over our tokenizer — exception (a).**
Scope it to what rendering needs, not the full spec:

- element/text/comment nodes in an arena (`Vec<Node>` — no boxing churn),
- implied tags (`<p>`, `<li>`, `<tr>`, table/row/cell fixups as far as needed),
- raw-text elements (`script`/`style`/`textarea` tokenized as text),
- **adoption-agency-lite**: properly nest what is nestable, close-on-mismatch
  instead of the full RFC algorithm — documented divergence, tested against
  malformed fixtures;
- entity decoding via the existing `decode_entities_into`.

Host-tested adversarially in a new crate (e.g. `dom`): deep-nesting bombs
(bounded depth → no stack overflow — recursion is the enemy: iterative
construction), unclosed-tag storms, attribute chaos, `<table>` mis-nesting,
bytes-vs-UTF-8. The "no unbounded recursion, no unbounded allocation" rules
mirror the rest of the tree.

## 5. CSS

| Candidate | no_std | Notes |
|---|---|---|
| `cssparser` (servo) | claimed "optional" in the no-std survey; unverified for our target | syntax-level parser only — **the cascade/selectors/style tree live in servo's `style` crate, which is not a standalone std-free dependency** |
| `selectors` (servo) | unverified; std-leaning | matching engine only |
| from-scratch subset | — | **decision below** |

Even if `cssparser` builds no_std, it buys only tokenization; the part that
matters (selector matching + cascade + computed values for our subset) would
still be ours. **Decision: a from-scratch CSS-subset parser + cascade —
exception (a)** (the usable standalone pieces are std-leaning servo internals;
costed at a few hundred lines for the v1 property set), with `cssparser` kept
as the tokenizer *if* its probe passes (decided at integration, recorded in the
commit either way). Property subset v1: `display` (none/block/inline),
`color`, `background-color` (mapped to VGA attributes), `font-weight`,
`font-style`, `text-decoration`, list properties, `width`/`height` (cell
units), margins/padding (cell units). Specificity + source order implemented
properly (it is ~30 lines and prevents a class of wrong renders).
B3 landed this as the **`csscore`** crate — §8 row B3 and the appendix
record the exact supported/ignored set, the units and the VGA color
mapping.

## 6. Layout + rendering

No crate exists for no-std browser layout (every engine is std) →
**from-scratch, exception (a) by definition**. Text-mode layout is a bounded
problem:

- block flow (stacking, margins collapsed in cells), inline flow (word wrap at
  cell width, `white-space` normal/pre), lists with markers, headings by
  scaling attributes (bold/dim), `<pre>`/`<code>` preserved whitespace;
- viewport = the TUI frame (A1), scroll with arrow keys/PageUp/Down;
- link highlighting (inverse cells) + numbered-link jump (Lynx-style `g` input
  is a nice-to-have; v1 = arrow navigation + Enter);
- charset: UTF-8 first (decode via the tokenizer's helpers), non-representable
  glyphs → `?` through the VGA font (CP437 mapping table is a later polish).

## 7. Networking specifics

- One `Connection: close` GET per request (our framer's model; HTTP keep-alive
  deferred — correctness over speed on a 5400 rpm link).
- Redirects: follow up to N=5 `3xx + Location` (resolved through `url`),
  refusing cross-protocol downgrades (https→http) — fail-closed like the rest.
- No `Accept-Encoding` sent ⇒ no gzip to decode (servers must honor identity).
- `User-Agent: reemplazo-browser/0.1`, `Accept: text/html,*/*;q=0.5`.
- Response body bounded (`READ_CAP`-style) — a hostile server cannot exhaust
  the heap; over-bound = fatal with a clear message.

## 8. Milestone plan

| # | Milestone | Build first / smoke marker | Depends on |
|---|---|---|---|
| B0 | *(shared prerequisite)* TUI screen layer — docs/ai-client.md milestone **A1** (`TUI_OK`) | — | — |
| B1 | URL parse/resolve + fetch with redirect loop against real hosts (GET only) | **`BROWSER_FETCH_OK`** (resolve+fetch github.com through ≥1 redirect, print status/final URL) | `url` probe, TLS |
| B2 | HTML tree builder crate (host tests) + text layout + render in the TUI viewport | **`BROWSER_RENDER_OK`** (landed: `dom` arena tree over the tokenizer, word-wrapped layout rendered in the viewport and read back from `0xb8000` — real page *and* a feature fixture, since today's example.com carries no `<h1>`/`<a>`) | B0, B1 |
| B3 | CSS subset: parser + cascade + attribute mapping | **`BROWSER_CSS_OK`** (landed: `csscore` parses/selects/cascades — type/class/id/`*`/compound/descendant/comma, specificity + source order + inline + `!important`; `display`, `color`, `background-color`→VGA attribute, `font-weight`→bright bit, `font-style`→dim, `text-decoration` parsed/no-op, `list-style-type`, `width`/`height`, `margin`/`padding` in cells; styled fixture vs unstyled twin asserted on exact attribute bytes/positions from `0xb8000`; real-page sheet applied as an unchecked robustness pass) | B2 |
| B4 | Navigation polish: history, link jump, status bar, error pages (DNS/refused/timeout → friendly page, never a hang) | **`BROWSER_NAV_OK`** (scripted key sequence follows a link and goes back) | B2 |
| later | GUI (A6), images, cookies, HTTP cache, keep-alive, JS stance revisit | separate research | — |

Order rationale: B1 is smoke-testable without the UI and de-risks `url`+redirects
early; B2 is the visible win; B3/B4 refine. Everything rides the A1 screen layer,
so the AI-client track (A1→A2→A3) and the browser track interleave cleanly:
**A1 first, then either track.**

## 9. Risks / open questions

- **`url` no_std probe unverified** (docs claim it; we have not cross-built it).
  Fallback costed in §3.
- **Real-web rendering variance**: sites assume CSS/JS we do not have; the
  honest test set is documentation-style pages (our own README on github raw,
  example.com, wikipedia mobile-agnostic HTML). Recorded as a scope limit, not
  a bug.
- **Malformed-HTML handling** (adoption-agency-lite) will differ from browsers
  on pathological pages — documented divergence + fixtures, per §4.
- **Memory**: a DOM for a big page (github.com HTML ≈ 300–800 KB) with heap
  nodes must stay bounded; arena + depth caps + body `READ_CAP` are the levers.
- **Smoke budget**: B1/B2 add real network round-trips to the 30 s boot smoke —
  measure; if too tight, keep the marker on a fast endpoint (example.com) and
  leave the heavy page to `cargo xtask run` manual runs.

## Appendix: verification log

- 2026-11-22 — **B3 landed** (`BROWSER_CSS_OK`, 27-marker chain):
  `csscore` (new workspace crate, exception (a) of §5) — `no_std` +
  `alloc`, zero deps, `forbid(unsafe_code)`, bounded input/rules/
  selectors/declarations, adversarial host tests (`cargo test -p
  csscore`: 66). Supported: type/`.class`/`#id`/`*`/compound/descendant
  selectors and comma lists; `display` (none/block/inline,
  `inline-block`→inline), `color`, `background-color`, `font-weight`
  (normal/bold/100–900), `font-style` (italic→dim), `text-decoration`
  (parsed; VGA has no underline), `list-style-type`
  (disc/circle/square, dash, none), `width`/`height` and
  `margin`/`padding` (1–4 value shorthand, cells; `px` = 8 px/cell
  rounded up, `%` for width only). Cascade: id > class > type summed
  over compounds, source order, inline `style=""`, `!important`
  implemented (`(important, inline, id, class, type, order,
  declaration)` — sheet-important beats inline-normal). Ignored
  (fail-soft per declaration, rule survives): child/sibling/attribute/
  pseudo selectors (selector dropped, comma list survives), `@media`/
  `@import`/`@font-face` (skipped whole), units other than
  `px`/bare/`%`-width, floats, `background`/`font` shorthands, external
  stylesheets (`<link rel=stylesheet>` fetching is out). Render:
  `display:none` skips the subtree, `color`/`background-color` become
  the cell's VGA attribute indices (nearest RGB over the 16-color table
  the tree already uses; ties → brighter; `yellow` → 11 because slot 3
  is olive), `font-weight` the bright bit, `font-style` the dark half,
  left margin/padding the block indent, top the blank-line count
  (capped), `width` the block's wrap width, `list-style-type` the
  marker; `background-color` inherits down the subtree (documented
  divergence — no block boxes are painted), `height` right/bottom
  margins are parsed but not applied by the flow. Proof: the fixture
  frame is asserted cell-by-cell (heading 0x09, `.box` background
  0xB7, `color:red` 0x01, bold 0x0F, `#id` 0x0E, inline 0x0B,
  margin+padding shift x=4, `display:none` absent) and the **same body
  without its sheet** re-asserts the plain heading attribute 0x0F,
  default 0x07 on a plain div, the previously hidden paragraph visible
  and x=0; the real example.com sheet parses (2 rules, all properties
  outside the subset) and is applied without assertions, so B2's
  example.com frame stays the unstyled regression net.
- 2026-11-22 — **B2 landed** (`BROWSER_RENDER_OK`, 25-marker chain):
  `dom` (new workspace crate, exception (a) of §4) builds an iterative
  arena tree with `DEPTH_CAP` 64 / `NODE_CAP` 4096 refused fail-closed
  and adoption-agency-lite rules documented in the crate docs — 38 host
  tests green (`cargo test -p dom`). The kernel lays the tree out for
  the text viewport and reads the rendered frame back from `0xb8000`
  (real page *and* an embedded feature fixture). Two recorded
  deviations: the fetch is `http://example.com` — today's TLS chain
  terminates at AAA Certificate Services, which `tls.rs`'s pinned
  USERTrust ECC root refuses (`tls.rs` outside B2's change set) — and
  the post-2023 example.com carries no `<h1>`/`<a>`, so heading/link/
  list/pre assertions run on the fixture frame while title, paragraph
  and word-wrap assertions run on the real page.
- 2026-11-21 — `url` no_std+alloc confirmed from docs.rs feature description
  ("The `alloc` feature provides no_std support") and servo/rust-url release
  notes; build probe deferred to milestone B1 start.
- 2026-11-21 — no maintained no_std HTML tree builder found (html5ever/
  markup5ever std; html5gum no_std failure is in-tree evidence in
  `html/src/lib.rs`).
- 2026-11-21 — cssparser/selectors: servo-standalone, std-leaning, cascade not
  in the standalone crates (survey + crates.io pages).
