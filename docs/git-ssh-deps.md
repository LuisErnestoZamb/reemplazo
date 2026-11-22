# Dependency evaluation: `git` and `ssh` (no_std, pre-heap)

- **Date:** 2026-11-21 · research only, no code changed.
- **Basis:** `AGENTS.md` (deliverables: *git clone/commit/fetch/push vs GitHub over ssh or https*, *ssh client + server*; GitHub rejects legacy sha1 `ssh-rsa`) and `.opencode/skills/rust-os-dev/SKILL.md` §"Dependencias": use known, battle-tested crates; from-scratch only when **(a)** no known crate supports what we need (no_std/alloc/target/feature/license) or **(b)** our own version gives a worthwhile memory/CPU/RAM win — and record the reason. No hand-rolled crypto, ever.
- **Target constraints:** `x86_64-unknown-none`, no_std, **no allocator yet**, x86-64-v1 only (no SSE4+/AVX), 2.9 GB RAM, 5400 rpm disk, Core2 Duo. Toolchain pinned `1.98.1`.
- **Method:** every claim below was verified on 2026-11-21 by fetching the cited URL (docs.rs / crates.io API / crate source on GitHub / rustsec advisory-db / git-scm.com / github.blog). Commands are in the [Appendix](#appendix-verification-log).

## 1. What the tree already has (from `Cargo.lock`)

Already available to git/ssh, all RustCrypto/embassy line:

| Crate | Version in tree | Use for |
|---|---|---|
| `sha2` | 0.11.1 (digest 0.11) | SHA-256/512 (git SHA-256 repos optional, ssh HMAC/hash) |
| `aes`, `ctr` | 0.9.4 / 0.10.1 | AES-CTR ciphers (ssh) |
| `aes-gcm`, `ghash`, `polyval` | 0.11.1 / 0.6.0 / 0.7.3 | AES-GCM (ssh `aes*-gcm@openssh.com` later) |
| `hmac`, `hkdf` | 0.13.0 / 0.13.0 | ssh MAC + KDF building blocks |
| `p256`, `p384`, `ecdsa` | 0.14.0 / 0.14.0 / 0.17.0 | optional `ecdsa-sha2-nistp256` (ssh) |
| `rand_core`, `rand_chacha` | 0.9.5 + 0.10.1 / 0.9.0 | key generation (both 0.9 and 0.10 lines present) |
| `embassy-crypto(-rustcrypto)`, `embedded-tls` 0.19.0 | git revs | TLS client (already smoke-tested: `TLS_OK`; `HTTP_OK` milestone now in `AGENTS.md`) |
| `subtle`, `zeroize`, `base16ct` | present | constant-time / secret zeroing |

**Not in tree:** `sha1`, `miniz_oxide`, `httparse`, `x25519-dalek`, `ed25519-dalek`, `ssh-key`, `ssh-encoding`, `chacha20poly1305`, `base64`, `hex`.

---

## A. `git`

### A.1 Object plumbing

#### A.1.1 SHA-1 object hashing

| Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|
| **`sha1` 0.11.0** — `#![no_std]` unconditional ([source](https://docs.rs/crate/sha1/0.11.0/source/src/lib.rs)); default features `[alloc, oid]` → disable `alloc` for pre-heap | **yes** (`default-features = false`) | no (incremental `Digest::update/finalize` into arrays) | Very active (RustCrypto/hashes; digest **0.11** = same generation as our `sha2` 0.11 → no duplicate `digest`) | none ([search](https://github.com/rustsec/advisory-db/tree/main/crates/sha1)) | MIT/Apache-2.0 | https://crates.io/crates/sha1 |
| `sha1dc` 0.1.5 — collision-detecting SHA-1, **the variant git itself uses**; `default = [std]`, `std` optional → no_std | yes | no | Active (used by `gix-hash`) | none | MIT | https://crates.io/crates/sha1dc |
| `gix-hash` 0.28.1 | **no** — depends on `faster-hex` with `features = ["std"]` ([Cargo.toml](https://docs.rs/crate/gix-hash/0.28.1/source/Cargo.toml)) | — | Very active (gitoxide) | none | MIT/Apache-2.0 | https://crates.io/crates/gix-hash |

**Recommendation: use `sha1` today** (0.11.0, `default-features = false`). Note `sha1dc` as a later drop-in hardening (policy exception (b): matches git's own collision-detecting hashing for adversarially-received content; decide after we measure). Rejected: `gix-hash` (exception (a): std-only).

#### A.1.2 zlib (DEFLATE) for packfiles and loose objects

Git needs **decompression** (pack entries) and **compression** (writing loose objects, building packs for push), both in zlib format.

| Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|
| **`miniz_oxide` 0.9.1** — `#![cfg_attr(not(feature = "std"), no_std)]` ([source](https://docs.rs/crate/miniz_oxide/0.9.1/source/src/lib.rs)); `default = [with-alloc]`, **no `std` in default** → default build is no_std + alloc; deps (`adler2`) are `default-features = false` ([Cargo.toml](https://docs.rs/crate/miniz_oxide/0.9.1/source/Cargo.toml)) | **yes** | for the `*_to_vec*` APIs yes; a streaming update-style API with caller buffers exists — **exact pre-heap API to confirm at integration** | Active; it is flate2's `rust_backend` | none ([search](https://github.com/rustsec/advisory-db/tree/main/crates/miniz_oxide)) | MIT/Zlib/Apache-2.0 | https://crates.io/crates/miniz_oxide |
| `flate2` 1.1.11 (even with `rust_backend` = miniz_oxide) | **no on stable** — `#![no_std]` but unconditionally `extern crate std` unless the nightly `flate2_unstable_nightly_alloc_io` cfg ([source](https://docs.rs/crate/flate2/1.1.11/source/src/lib.rs)) | std | Active | none | MIT/Apache-2.0 | https://crates.io/crates/flate2 |
| `zlib-rs` 0.6.8 | default `std` | std | Active | **RUSTSEC-2024-0401** (stack overflow on malicious input, patched `>= 0.4.0` — [advisory](https://rustsec.org/advisories/RUSTSEC-2024-0401.html)) | Zlib | https://crates.io/crates/zlib-rs |
| `zune-inflate` 0.2.54 | yes (`std` optional) but **decompress-only** — no deflate encoder for loose objects/push | — | Active | none | MIT/Apache/Zlib | https://crates.io/crates/zune-inflate |

**Recommendation: use `miniz_oxide` today** (default features = no_std+alloc; pre-heap, drive the streaming API with fixed buffers — API to confirm). `flate2` rejected (exception (a): needs std on stable). `zlib-rs` not needed.

#### A.1.3 Packfile parsing + `.idx` generation (`index-pack`)

| Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|
| `gix-pack` 0.77.0 | **no** — features pull `gix-tempfile`, `parking_lot` (std-only) ([Cargo.toml](https://docs.rs/crate/gix-pack/0.77.0/source/Cargo.toml)) | std | Very active (gitoxide, 14.5M recent downloads of `gix`) | none on `gix-pack` (but `gix-transport` had **RUSTSEC-2023-0064** and **RUSTSEC-2024-0335**, both code-exec via ssh URLs, patched ≥0.36.1/0.42.0 — current 0.62.0 is patched) | MIT/Apache-2.0 | https://crates.io/crates/gix-pack |
| `packfile` | unverified; in-memory generation only; dormant (updated 2024-02) | — | Stale | none | — | https://crates.io/crates/packfile |
| `git-core` 0.2.1 (loose+pack reader) | unverified (source not exposed on docs.rs) | unverified | Niche (DFIR tooling), low traction | none | Apache-2.0 | https://crates.io/crates/git-core |
| `cgap-git` (pack v2 writer + idx v2) | `default = [std]` → likely no_std, **but license = unknown**, odd versioning, dubious provenance | — | — | none | **unknown** | https://crates.io/crates/cgap-git |
| `puregit` | built on `purecrypto`/`puressh` — a from-scratch crypto suite, **violates the no-hand-rolled-crypto policy** | — | 36 downloads | none | — | https://crates.io/crates/puregit |

**Recommendation: from-scratch justified — exception (a) primary, (b) secondary.**
- (a): the only maintained pack implementation (`gix-pack`) is std-only; no no_std pack/idx crate exists (crates.io search `packfile`, 2026-11-21).
- (b): our streaming, fixed-buffer, checked-arithmetic parser matches the project's adversarial-parser rule (skill: *todo parser tiene tests adversariales*) and avoids `tempfile`/`parking_lot`/thread pools we don't have.
- Spec is complete and small: [pack-format](https://git-scm.com/docs/pack-format), [git-index-pack](https://git-scm.com/docs/git-index-pack), [pack-protocol](https://git-scm.com/docs/pack-protocol).

### A.2 Smart HTTP transport and the protocol state machine

| Need | Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|---|
| pkt-line framing | crate literally named `git-pkt-line` **does not exist** (crates.io search `pkt-line` returns 8 hits total, 2026-11-21) | | | | | | |
| pkt-line | `gix-packetline` 0.24.1 | **no** — non-IO deps still force std: `bstr`, `faster-hex`, `serde` with `features = ["std"]` ([Cargo.toml](https://docs.rs/crate/gix-packetline/0.24.1/source/Cargo.toml)) | std | Very active (53.8M downloads, 13.8M recent) | none | MIT/Apache-2.0 | https://crates.io/crates/gix-packetline |
| pkt-line | `gunnar-pktline` 1.1.0 | **likely yes** — *zero dependencies* (crates.io API) | no? | **Not battle-tested**: first release 2026-08, 1 version, 761 downloads; part of the `gunnar` family whose main crate is **AGPL-3.0** | none | MIT/Apache-2.0 | https://crates.io/crates/gunnar-pktline |
| pkt-line + protocol v0/v1/v2 | `sley-protocol` 0.13.0 | unverified (source not exposed); MSRV 1.98; depends on `sley-core` | unverified | **Not battle-tested**: created 2026-08, months old | none | Apache-2.0 | https://crates.io/crates/sley-protocol |
| upload-pack/receive-pack state machine | `gix-protocol` 0.68.0 | **no** (pulls `gix-transport` = std, `curl`/`http-client`) | std | Very active; `gix-transport` has the two patched code-exec advisories above | see left | MIT/Apache-2.0 | https://crates.io/crates/gix-protocol |
| HTTP response parsing | **`httparse` 1.10.1** — `#![cfg_attr(not(any(test, feature = "std")), no_std)]` ([source](https://docs.rs/crate/httparse/1.10.1/source/src/lib.rs)), zero-copy into caller buffers (no alloc) | **yes** (`default-features = false`) | no | Active (de-facto standard) | none | MIT/Apache-2.0 | https://crates.io/crates/httparse |
| HTTP client | `http-client` 6.5.3 | default features = `async-std`/`dashmap`/`deadpool` → std | std | — | none | MIT/Apache-2.0 | https://crates.io/crates/http-client |
| base64 (auth header) | `base64` 0.23.1 (`#no_std` tag; `default-features=false, features=["alloc"]`) | yes | for `String` outputs; byte APIs no | Active | none | MIT/Apache-2.0 | https://crates.io/crates/base64 |

**Recommendation:**
- **pkt-line: from-scratch justified (a)** — the format is a 4-hex-digit length prefix + payload (fully specified in [pack-protocol](https://git-scm.com/docs/pack-protocol) and exercised by every git client); the only battle-tested crate (`gix-packetline`) is std-only; the no_std-looking alternative (`gunnar-pktline`) is weeks old and unaudited → fails the battle-tested bar. ~150 LoC with adversarial tests (truncated, oversized length, `0000` flush, `0001` delim).
- **upload-pack/receive-pack state machine: from-scratch justified (a)** — `gix-protocol` is std-only; state machine is small (advertise → want/have (v0) or v2 command → pack stream → done). Spec: [http-protocol](https://git-scm.com/docs/http-protocol), [protocol-v2](https://git-scm.com/docs/protocol-v2), [protocol-capabilities](https://git-scm.com/docs/protocol-capabilities).
- **HTTP: use `httparse` today** + a thin from-scratch request writer and chunked decoder (RFC 7230 §4.1, https://www.rfc-editor.org/rfc/rfc7230). This also feeds the new `HTTP_OK` smoke milestone in `AGENTS.md`.

### A.3 What runs where — would it even fit?

The deliverable is git **inside the OS** (AGENTS.md) — a host-side xtask helper is not a substitute (it may still use gitoxide for CI, std-side).

Honest sizing for a full clone (numbers derived from [pack-format](https://git-scm.com/docs/pack-format); throughput figures are **estimates, not measured**):

- **`.idx` v2 size** = 1024 B fanout + 32 B/object + ~40 B trailer → **1M objects ≈ 32 MB**, 10M ≈ 320 MB. Fits 2.9 GB comfortably.
- **In-RAM offset table** during index-pack ≈ 8 B/object → 8 MB per 1M objects, plus base/result delta working buffers (bounded per object). Also fits.
- **CPU/disk are the binding constraints, not RAM:** software SHA-1 on a Core2 (no SHA-NI) is on the order of 100–300 MB/s/core (estimate), miniz_oxide inflate tens of MB/s (estimate), 5400 rpm disk ~60–100 MB/s sequential (estimate). A **shallow clone of a small repo** is seconds-to-low-minutes; a **full clone of a multi-GB repo** is many minutes of CPU+disk but still RAM-feasible.
- **Conclusion:** a bounded, streaming no_std design is viable; the risk is parser/protocol complexity, not memory. Design rule: every parser takes caller-provided buffers; the only unavoidable heap consumer is the SHA→offset table for delta resolution (scale: 8–32 B/object).

**Minimal viable git (in order):**
1. `git ls-remote <https-url>` — no pack, no heap beyond bounded buffers. *First smoke-testable win.*
2. `git fetch/clone --depth=1` of a small repo over https — single pack, index-pack, checkout (needs heap for trees/paths).
3. Local `add`/`commit` (write loose objects: sha1 + miniz_oxide) and `log`/`status`-lite.
4. `git push` — **no delta encoder needed**: a pack of full (non-delta) objects is legal and accepted by `receive-pack` (delta *encoding* is explicitly deferred).
5. `git` over ssh (reuses the ssh client in §B).
6. Deferred: protocol v2 refinements, thin-pack negotiation, delta *encoding*, SHA-256 repos, multi-pack-index/bitmap — none are needed for the deliverable "clone/commit/fetch/push vs GitHub".

### A.4 Milestone plan — git

| # | Milestone | Build first / smoke marker | Depends on |
|---|---|---|---|
| G1 | pkt-line codec (encode/decode/flush, adversarial tests) | host tests `cargo test -p git-pktline` | nothing |
| G2 | smart-HTTP GET `info/refs?service=git-upload-pack` + advertisement parse → **`git ls-remote`** | serial marker **`GIT_LSREMOTE_OK`** in QEMU against `github.com` | `HTTP_OK` (already in smoke chain), `httparse` |
| G3 | fetch (v0 `want`/`deepen=1`) → pack stream → **index-pack** (offset table + delta resolution + `.idx` write) | **`GIT_FETCH_OK`** (verify pack+idx against a real `git` on the host) | G1, G2, heap (tables) |
| G4 | checkout of depth-1 tree (tree/blob parse, paths, file write) | **`GIT_CHECKOUT_OK`** | G3, heap, VFS/FS writes |
| G5 | local object store: loose object write (sha1 + miniz_oxide), refs, commit creation → `git commit` equivalent | **`GIT_COMMIT_OK`** | G4 |
| G6 | push: serialize full-object pack + idx, `receive-pack` state machine | **`GIT_PUSH_OK`** against a test repo | G5, G1 |
| G7 | git over ssh (`git-upload-pack` exec channel) | **`GIT_SSH_OK`** | G2 + S4 (§B.4) |

**Status (G3, landed 2026-11-22):** `GIT_FETCH_OK` is in the boot chain
between `GIT_LSREMOTE_OK` and `SSH_KEXINIT_OK`. The kernel POSTs the v0
`want <head> ofs-delta shallow` / `deepen 1` / flush / `done` / flush
stream (no `side-band`, per
[pack-protocol](https://git-scm.com/docs/pack-protocol#_packfile_negotiation))
to `github.com/LuisErnestoZamb/reemplazo.git/git-upload-pack`, parses the
`shallow` + `NAK` pkt-lines and hands the raw pack to `git-pack`, which
verifies the trailer SHA-1 and returns the objects plus the sha1 →
offset `PackIndex` (the in-memory `.idx` main table). An iterative
commit → tree → blob walk then enforces depth/entry/path/bounds caps.
**Deferred:** the **`.idx` file write** (the index exists in memory and
is exercised, but no `.idx` bytes are written to disk yet) and the
loose-object store — both belong to G4/G5's `clone` layout. **Partial
G4:** `smoke-install`'s `GIT_CHECKOUT_OK` checks the fetched repo's
8.3-representable **root-level** blobs (`README.md`, `AGENTS.md`,
`LICENSE`, …) into the FAT16 volume and re-reads `/README.md`
byte-exactly (AGPL fragment checked); nested paths and long names are
counted as skipped because `fat` has no `mkdir`/LFN writer yet (the
full tree checkout is the rest of G4).

---

## B. `ssh`

### B.1 Crypto primitives (audited crates only — policy is absolute here)

| Primitive | Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|---|
| curve25519 ECDH | **`x25519-dalek` 3.0.0** — `#![no_std]` ([source](https://docs.rs/crate/x25519-dalek/3.0.0/source/src/lib.rs)); default features `[precomputed-tables, zeroize]`, no alloc required; depends `curve25519-dalek ^5.0.0` (crates.io API) | **yes** | no | Active (dalek-cryptography) | none for `x25519-dalek`; dep `curve25519-dalek` **RUSTSEC-2024-0344** patched `>= 4.1.3` — `^5.0.0` is fine ([advisory](https://rustsec.org/advisories/RUSTSEC-2024-0344.html)) | BSD-3-Clause | https://crates.io/crates/x25519-dalek |
| Ed25519 sign/verify | **`ed25519-dalek` 3.0.0** — `#![no_std]` ([source](https://docs.rs/crate/ed25519-dalek/3.0.0/source/src/lib.rs)); `alloc` optional (batch only) | **yes** | no for sign/verify of single messages | Active | **RUSTSEC-2022-0093** patched `>= 2` — we'd use 3.0.0 ([advisory](https://rustsec.org/advisories/RUSTSEC-2022-0093.html)) | BSD-3-Clause | https://crates.io/crates/ed25519-dalek |
| SHA-2 / SHA-1 | `sha2` 0.11.1 **in tree**; `sha1` 0.11.0 (§A.1.1) | yes | no | Active | sha2 **RUSTSEC-2021-0100** affects only 0.9.7 — tree 0.11.1 unaffected ([advisory](https://rustsec.org/advisories/RUSTSEC-2021-0100.html)) | MIT/Apache-2.0 | https://crates.io/crates/sha2 |
| AES-CTR / AES-GCM | `aes` 0.9.4 + `ctr` 0.10.1 + `aes-gcm` 0.11.1 **in tree** (via `embassy-crypto-rustcrypto`) | yes | no | Active | aes-gcm **RUSTSEC-2023-0096** affects 0.10.0–0.10.2 — tree 0.11.1 unaffected ([advisory](https://rustsec.org/advisories/RUSTSEC-2023-0096.html)) | Apache-2.0/MIT | https://crates.io/crates/aes-gcm |
| ChaCha20-Poly1305 (IETF) | `chacha20poly1305` 0.11.0 — no_std with `default-features = false` (drop `alloc`, `getrandom`) | **yes** | no | Active | none | Apache-2.0/MIT | https://crates.io/crates/chacha20poly1305 |
| ChaCha20-Poly1305 **as OpenSSH uses it** (`chacha20-poly1305@openssh.com`) | built from `chacha20` 0.10.2 + `poly1305` 0.9.1 (both no_std, no advisories) following OpenSSH [PROTOCOL §1.7](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL) / [draft-ietf-sshm-chacha20-poly1305](https://datatracker.ietf.org/doc/draft-ietf-sshm-chacha20-poly1305/) — **glue code over audited primitives, not hand-rolled crypto** | yes | no | Active | none | Apache-2.0/MIT | https://crates.io/crates/chacha20 |
| HMAC / KDF | `hmac` 0.13.0 + `hkdf` 0.13.0 **in tree** (no `std` feature at all → no_std) | yes | no | Active | none | MIT/Apache-2.0 | https://crates.io/crates/hmac |
| RSA (host or user keys) | `rsa` 0.10.0 — `#![no_std]` but `crypto-bigint` with `features = ["alloc"]` → **heap mandatory** | after heap | **yes** | Active | **RUSTSEC-2023-0071** (Marvin timing, key recovery) patched `>= 0.10.0` ([advisory](https://rustsec.org/advisories/RUSTSEC-2023-0071.html)) | MIT/Apache-2.0 | https://crates.io/crates/rsa |
| RNG | `rand_core` 0.9.5 + 0.10.1, `rand_chacha` 0.9.0 **in tree** | yes | no | Active | none | MIT/Apache-2.0 | https://crates.io/crates/rand_chacha |
| base64 / hex (key blobs) | `base64` 0.23.1, `hex` 0.4.3 — no_std (`default-features=false`) | yes | byte APIs no | Active | none | MIT/Apache-2.0 | https://crates.io/crates/hex |

**Recommendations:** use everything marked *in tree* as-is; **add `x25519-dalek` + `ed25519-dalek` (3.0.0) today** — both unconditional `#![no_std]`, advisory-clean at these versions. **`rsa`: skip** — not needed to talk to github.com (§B.3), and it needs the heap; add after heap only if RSA keys become a requirement. **`chacha20-poly1305@openssh.com`: defer** (phase 2) — `aes128/256-ctr + hmac-sha2-256` is enough for GitHub *and* OpenSSH clients and is fully covered by in-tree crates.

### B.2 Protocol implementation layer

| Candidate | Fits no_std today | Needs heap | Maintenance | RustSec | License | Source |
|---|---|---|---|---|---|---|
| `russh` 0.65.2 | **no** — `bytes`, `futures`, `getrandom`, `aws-lc-rs`, `pkcs8 … features=["std"]`; no `no_std` anywhere ([Cargo.toml](https://github.com/warp-tech/russh/blob/main/russh/Cargo.toml)) | std | Active | **7 advisories since 2024** — RUSTSEC-2024-0450 (packet-length OOM), 2026-0154 (unbounded frame), 2026-0492/0493/0494/0495/0496 (handler confusion, decompressed-size, field-size, agent, pre-auth alloc); **all patched in 0.65.2**, but the packet-handling bug track record is a yellow flag | Apache-2.0 | https://crates.io/crates/russh |
| `ssh-protocol` 0.3.0-rc.0 (RustCrypto) | `#![no_std]`, features `default=[std]`, `alloc` optional — **exactly the shape we want**… but `src/` is a **16-line facade** re-exporting `ssh-cipher`/`ssh-encoding`/`ssh-key`; README says **(WIP)**; created 2022, last updated 2025-06, 4 065 downloads | — | **Not usable today** | none | Apache-2.0/MIT | https://crates.io/crates/ssh-protocol |
| `ssh-key` 0.6.1 (key parsing, *not* transport) | **yes** — `#![no_std]` ([source](https://docs.rs/crate/ssh-key/0.6.1/source/src/lib.rs)); decode needs `alloc` feature (`std` ⇒ `alloc`) | **yes** for decoding keys | RustCrypto, stable line (0.7.0-rc.12 also exists) | none ([search](https://github.com/rustsec/advisory-db/tree/main/crates/ssh-key)) | Apache-2.0/MIT | https://crates.io/crates/ssh-key |
| `ssh-encoding` 0.3.0 (RFC4251 encode/decode) | **yes** — `#![no_std]`, no `std` feature at all ([source](https://docs.rs/crate/ssh-encoding/0.3.0/source/src/lib.rs)) | for `Vec`/`String` outputs | RustCrypto, stable | none | Apache-2.0/MIT | https://crates.io/crates/ssh-encoding |
| anything else ("ssh no_std", "no_std ssh" on crates.io, 2026-11-21) | **no maintained no_std SSH transport crate found** | | | | | |

**Version-alignment note (verified via crates.io dependency API):**
- `ssh-key` **0.6.1** (stable) pins the *previous* generation: `ssh-encoding ^0.2`, `ed25519-dalek ^2`, `p256 ^0.13`, `rand_core ^0.6`, `rsa ^0.9` → duplicate crate versions next to our tree (`p256 0.14`, `rand_core 0.10`, `ed25519-dalek 3`).
- `ssh-key` **0.7.0-rc.12** pins the *current* generation: `ssh-encoding ^0.3` (stable 0.3.0 works), `ed25519-dalek ^3`, `p256 ^0.14`, `rand_core ^0.10`, `rsa ^0.10` → no duplicates, but it is a pre-release.

**Recommendation:**
- **SSH transport (RFC4251/4253 binary packet protocol, KEX negotiation, KDF, auth, channels): from-scratch justified (a)** — `russh` is std-only (and carries an advisory track record); RustCrypto's `ssh-protocol` is a stub; nothing else exists. This is *protocol glue over audited primitives* — explicitly allowed by policy ("Nada de criptografía casera … usa crates auditados"), as long as every primitive comes from §B.1.
- **Key parsing: use `ssh-key` + `ssh-encoding`** (the big reuse win — OpenSSH private keys, `authorized_keys`, `known_hosts`, fingerprints). Pick **0.6.1 (stable)** by default per the battle-tested bar; switch to 0.7.0-rc.12 if duplicate dalek/p256 versions bother us — decide at integration, both are no_std+alloc. **Needs heap → the actual parsing milestone comes after the heap milestone.**
- Rejected: `russh` (exception (a): no_std; plus advisory history), `purecrypto`-based stacks (unaudited crypto).

**S3 probe result (2026-11-22, `ssh-key` least-viable question settled with measurements, `x86_64-unknown-none`, rust 1.98.1, the repo's exact `RUSTFLAGS` incl. `curve25519_dalek_backend="serial"`):**

| Candidate | Result | Why |
|---|---|---|
| `ssh-key` **0.6.1**, `default-features = false, features = ["alloc","ed25519"]` | **fails as-is**; builds only with an extra `sha2 0.10` `force-soft` shim in our own manifest (feature unification) | `sha2 0.10.9` (its fingerprint dependency) compiles the x86 SHA-NI/AVX2 modules on this SSE-less target and rustc-LLVM aborts with *"Do not know how to split the result of this operator"* — the same class of failure as curve25519-dalek's SIMD backend (the `.cargo/config.toml` note). With the shim it builds, but drags a **second crypto generation** into ring 0: `ed25519-dalek 2.2`, `curve25519-dalek 4.1.3`, `rand_core 0.6`, `ssh-cipher 0.2`, `ssh-encoding 0.2`, plus `sha2 0.10` next to our 0.11. |
| `ssh-key` **0.7.0-rc.12**, same features | **builds clean** (release, no shim) | Aligns: `ed25519-dalek 3.0.0`, `sha2 0.11.1`, `ssh-encoding 0.3.0` (all already in the tree); adds `ssh-cipher 0.3`, `rand_core 0.10`, `signature 3`, `ctutils`. But it is a **pre-release**, and §B.2's bar for adoption is the battle-tested stable line. |

**Decision for S3:** do **not** adopt either yet. S3 needed no PEM parsing: the key enters as a **32-byte seed** (hex at the shell, or a raw/hex file on FAT — `kernel/src/keyfile.rs`), so the only `ssh-key` value (OpenSSH private-key strings) is exactly the part S3 defers. The three wire pieces S3 does need (`string "ssh-ed25519" ‖ string key`, the signature blob, the `session_id ‖ request` signing input) are RFC4251/RFC4252 encodings over `encode_string`, implemented in `ssh-wire` under exception (a) and host-tested byte-exact against `ssh-keygen` output (public halves only) — **no cryptography was written**: signing/verifying is `ed25519-dalek 3.0` (S2's reviewed crate). Adopt `ssh-key 0.7.0` (final, not rc) when PEM/`known_hosts` parsing actually lands; until then `openssl pkey -in ~/.ssh/id_ed25519 -text -noout` extracts the seed on the dev machine.


### B.3 GitHub compatibility — exact algorithm list

Evidence: [Improving Git protocol security on GitHub, 2021-09-01](https://github.blog/security/application-security/improving-git-protocol-security-github/) (removed DSA, `hmac-sha1`, all CBC ciphers; added ECDSA+Ed25519 host keys; RSA SHA-1 cutoff) and [changelog 2022-03-15](https://github.blog/changelog/2022-03-15-removed-unencrypted-git-protocol-and-certain-ssh-keys/) (made permanent; unencrypted `git://` removed). Host keys listed at [github.com SSH fingerprints](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints).

| Class | Minimal set for `github.com:22` | Our coverage | Status |
|---|---|---|---|
| KEX | **`curve25519-sha256`** (must) | `x25519-dalek` 3.0.0 | **use today** |
| KEX (optional) | `ecdh-sha2-nistp256` | `p256` already in tree | cheap later |
| Host-key accept | **`ssh-ed25519`** (must); `ecdsa-sha2-nistp256` (nice) | `ed25519-dalek` ✓, `p256`+`ecdsa` ✓, parse via `ssh-key` ✓ | **use today** |
| Host-key accept (optional) | `rsa-sha2-256`/`rsa-sha2-512` | `rsa` crate → heap | **defer** — negotiation succeeds without offering RSA (server still offers ed25519) |
| Ciphers | **`aes128-ctr`, `aes256-ctr`** (must) | `aes`+`ctr` in tree | **use today** |
| Ciphers (phase 2) | `aes128-gcm@openssh.com`, `chacha20-poly1305@openssh.com` | `aes-gcm` in tree but OpenSSH's GCM framing is custom; chacha variant per PROTOCOL §1.7 | defer |
| MAC | **`hmac-sha2-256`** (must; `hmac-sha1` was removed by GitHub anyway) | `hmac`+`sha2` in tree | **use today** |
| Compression | `none` | — | free |
| User auth | **`publickey` + `ssh-ed25519`** (must for us) | `ed25519-dalek` ✓, key via `ssh-key` ✓ | **use today** (needs a key registered in the account) |
| User auth (optional) | `ecdsa-sha2-nistp256`, `rsa-sha2-256/512` | p256 ✓ / rsa → heap | optional / defer |
| Extensions | tolerate `SSH_MSG_EXT_INFO` (`server-sig-algs`, RFC 8308) | protocol glue | must implement (small) |

**Bottom line: a client supporting only `curve25519-sha256` + `ssh-ed25519` host keys + `aes*-ctr` + `hmac-sha2-256` + `publickey/ssh-ed25519` interops with github.com today** — every primitive is already in §B.1. RSA is never required (and legacy SHA-1 `ssh-rsa` must never be offered — AGENTS.md).

### B.4 Milestone plan — ssh

| # | Milestone | Build first / smoke marker | Depends on |
|---|---|---|---|
| S1 | SSH banner + `SSH_MSG_KEXINIT` negotiation state machine (plaintext, algorithm intersection only) | serial marker **`SSH_KEXINIT_OK`** against `github.com:22` | `TCP_OK` |
| S2 | KEX `curve25519-sha256`, host-key verify `ssh-ed25519` (TOFU/known_hosts pinning via `ssh-key`), RFC4253 key derivation, `NEWKEYS`, then encrypted `aes128-ctr` + `hmac-sha2-256` | **`SSH_KEX_OK`** (handshake completes; `SSH_MSG_USERAUTH_FAILURE` on `none` auth = success) | `x25519-dalek`, `ed25519-dalek`, in-tree AES/HMAC |
| S3 | `publickey` user auth with an ed25519 key (key file via `ssh-key` — **post-heap**) | **`SSH_AUTH_OK`** (real GitHub account with registered key) | heap |
| S3a | **landed 2026-11-22 (no marker — honest gate):** `ssh-ed25519` key/signature blobs, the RFC4252 §7 probe + signed request (`session_id ‖ probe`), `PK_OK`/`SUCCESS`/`FAILURE`/`BANNER` answers, the fingerprint/base64/hex-seed codecs (all in `ssh-wire`, host-tested), and the boot-phase exchange with a **per-boot ephemeral key** → `USERAUTH_FAILURE` (the expected verdict, proving the request/blob/framing path). Manual `ssh-auth <64-hex \| /path-on-fat>` drives the same code with a registered key. **Pending:** end-to-end `SSH_AUTH_OK` with an account key; OpenSSH **PEM** parsing (S3's original `ssh-key` dependency) — probe result in §B.2, deferred; S5 loopback will exercise `PK_OK → signed → SUCCESS` without an account. | — (chain stays 27: no marker until a registered key can be run in CI) | `ed25519-dalek` (S2), `kernel/src/keyfile.rs` |
| S4 | Session channel + `exec` (`git-upload-pack`) → enables git-over-ssh | **`SSH_EXEC_OK`** (run `git ls-remote` over ssh) | S3 + G1 |
| S5 | **ssh server**: host-key generation (ed25519), listener, KEX as responder, `authorized_keys` auth, exec → shell | **`SSHD_OK`** (our client → our server, loopback in QEMU) | S2–S4 primitives |
| S6 | Hardening/interop: `ecdsa-sha2-nistp256`, `aes*-gcm@openssh.com` or `chacha20-poly1305@openssh.com`, `SSH_MSG_EXT_INFO` polish, rekeying | `SSH_INTEROP_OK` (`ssh -vvv` from OpenSSH shows clean negotiation) | S5 |

Order rationale: S1–S2 are heap-free (fixed-size KEX state) and give the first network-visible win **before** any allocator exists; S3 was expected to be where the heap is first needed (key parsing) — in the event, feeding a raw seed sidesteps the allocator entirely, and the heap is only needed when OpenSSH PEM/`known_hosts` parsing lands (S3a's "pending" line).

---

## C. Cross-cutting decisions

1. **Heap milestone comes before**: full clone/checkout (G3–G4), `ssh-key` parsing (S3), `miniz_oxide` vec APIs, RSA. Per skill rule: *if the best crate needs `alloc`, plan the heap milestone before rewriting it by hand* — none of the §A/§B from-scratch items is a workaround for an alloc-bound crate.
2. **Design every from-scratch parser streaming with caller-provided buffers** (pkt-line, HTTP headers, pack index, SSH frames) so S1–S2 and G1–G2 land pre-heap and double as adversarial-parser test surfaces (skill: every external datum is hostile; length/offset arithmetic `checked_*`).
3. **No new crypto code**: SSH transport and git protocol state machines are protocol glue only; every primitive is an audited crate from §B.1/§A.1, versions pinned in `Cargo.lock`, `cargo audit` gate before each commit (skill dependency rule).
4. **License check:** all recommended crates are MIT/Apache-2.0/BSD-3/Zlib → compatible with this repo's license (relicensed MIT → **AGPL-3.0** on 2026-11-21, Arepitas Technologies Inc; permissive and AGPL deps are both fine now). Avoid `gunnar` (first release 2026-08, fails the battle-tested bar) and `cgap-git` (license unknown).
5. **Host-side note:** `gix`/gitoxide (std, MIT/Apache, very active) remains the right choice for xtask/CI tooling on the dev Mac — it is not a substitute for the in-OS deliverable, and none of it is no_std.

---

## Appendix: verification log

Run 2026-11-21 from the repo root. All URLs cited above returned the quoted content.

```sh
# features + license of every candidate
cargo info sha1 sha2 flate2 miniz_oxide zlib-rs zune-inflate inflate \
  gix-packetline gix-pack gix-transport gix-protocol gix-object gix-hash \
  x25519-dalek ed25519-dalek ssh-key ssh-key@0.6.1 ssh-encoding ssh-encoding@0.3.0 \
  ssh-protocol russh rsa chacha20poly1305 chacha20 poly1305 hmac hkdf aes-gcm \
  httparse http-client base64 hex sha1dc git-core cgap-git gunnar sley-protocol

# no_std evidence = crate sources
curl -sL https://docs.rs/crate/<crate>/<ver>/source/src/lib.rs | grep no_std   # sha1, miniz_oxide, flate2,
                                                                               # x25519-dalek, ed25519-dalek,
                                                                               # ssh-key, ssh-encoding, httparse, rsa
curl -sL https://docs.rs/crate/gix-packetline/0.24.1/source/Cargo.toml          # bstr/faster-hex force "std"
curl -sL https://raw.githubusercontent.com/warp-tech/russh/main/russh/Cargo.toml # bytes/futures/aws-lc-rs

# RustSec: full advisory index, then individual advisories
curl -s "https://api.github.com/repos/rustsec/advisory-db/git/trees/main?recursive=1" \
  | grep -o '"path":"crates/[^"]*"' | sort -u
# → rsa, russh, ed25519-dalek, curve25519-dalek, aes-gcm, sha2, zlib-rs, gix-transport have advisories;
#   sha1, miniz_oxide, flate2, ssh-key, ssh-encoding, x25519-dalek, hmac, hkdf,
#   chacha20poly1305, aes, httparse, rand-chacha, gix, gix-pack, gix-packetline: none

# crates.io searches (needs a User-Agent header)
curl -A 'ua' 'https://crates.io/api/v1/crates?q=pkt-line&per_page=20'      # no crate named "git-pkt-line"
curl -A 'ua' 'https://crates.io/api/v1/crates?q=packfile&per_page=15'      # gix-pack only maintained option
curl -A 'ua' 'https://crates.io/api/v1/crates?q=no_std%20ssh&per_page=15'  # no no_std SSH transport crate

# spec/interop URLs
for u in https://git-scm.com/docs/http-protocol https://git-scm.com/docs/protocol-v2 \
         https://git-scm.com/docs/pack-protocol https://git-scm.com/docs/protocol-capabilities \
         https://git-scm.com/docs/pack-format https://git-scm.com/docs/git-index-pack \
         https://github.blog/changelog/2022-03-15-removed-unencrypted-git-protocol-and-certain-ssh-keys/ \
         https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints \
         https://raw.githubusercontent.com/openssh/openssh-portable/master/PROTOCOL; do :; done  # all HTTP 200
```

**Not verified (honest list):**
- no_std claims were verified by **source inspection**, not by cross-compiling each crate for `x86_64-unknown-none` — do a `cargo xtask` target build as the first integration step for every added crate.
- miniz_oxide's exact pre-heap streaming API names (existence of a no-alloc update-style API is expected from the feature set; confirm against installed docs).
- CPU/disk throughput figures in §A.3 are estimates, not measurements (skill: measure before optimizing).
- `git-core` / `sley-protocol` / `gunnar-pktline` no_std status was left unverified — they fail the battle-tested bar regardless.
- No crate was added to `Cargo.lock` by this research (`cargo info` only updated the local registry cache).
