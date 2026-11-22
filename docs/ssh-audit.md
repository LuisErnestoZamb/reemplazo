# SSH server audit — `kernel/src/sshd.rs` (milestone `ssh-hardening`)

**Date:** 2026-11-22 · **Branch:** `m-ssh-hardening` · **Mode:** read-only review of
`kernel/src/sshd.rs` (another agent owns that file right now — *nothing in it was
edited for this milestone*). The findings below are for the owner to apply; each
one carries a suggested fix.

**Scope:** `auth_request`, the channel/`exec` handling (`channel_phase`,
`run_command`), `recv_banner`, `Conn::recv`/`recv_into`, `recv_plain`,
`send_all`/`send_plain`, the accept windows in `serve_once`, and the buffer
limits `PAYLOAD_CAP` (1024) / `SANITIZE_CAP` (200) / `RX_CAP` (4096) /
`LAST_FAIL_CAP` (160). Reviewed against RFC4253 (transport), RFC4252 (auth),
RFC4254 (connection layer).

**Method:** line-by-line trace of every path a wire byte can take into a
decision, a log line, a buffer index or a loop condition; cross-checked
against `ssh-wire`'s host-tested parsers (this milestone added the adversarial
tests listed at the end). The companion crate was also re-audited for `unsafe`
and network-data `unwrap`/`expect` — results in §"ssh-wire hygiene".

## Severity summary

| # | file:line | finding | severity |
|---|-----------|---------|----------|
| F1 | `sshd.rs:506-563`, `717-774`, `816-830` | no overall session deadline; non-progress messages keep the (boot-blocking) session alive forever | **alto** |
| F2 | `sshd.rs:254-258` | session-error path returns without closing the socket | **medio** |
| F3 | `sshd.rs:101-102` vs `:94`, `:987-989` | advertised `MAX_PACKET` 32 KiB ≫ receive copy cap 1024 → we drop what we promised to accept | **medio** |
| F4 | `sshd.rs:595-615` | no user binding: the one authorized key authenticates as *any* user name | **medio** |
| F5 | `sshd.rs:726-732`, `:689-691` | unsupported channel request/type with payload → connection drop instead of `CHANNEL_FAILURE`/`CHANNEL_OPEN_FAILURE` | **bajo** |
| F6 | `sshd.rs:682-692`, `:793-812` | client's `initial_window`/`max_packet` are never validated or honored | **bajo** |
| F7 | `sshd.rs:558-561`, `:749-752`, `:820-824` | `SSH_MSG_IGNORE`/`DEBUG`/`UNIMPLEMENTED` treated as fatal (RFC4253 §6.1 requires receiving them) | **bajo** |
| F8 | `sshd.rs:530-541`, `:127-140` | previous session's internal failure reason replayed as a *pre-auth* banner | **bajo** |
| F9 | `sshd.rs:108`, `:122-123`, `:296-297` | `static mut` buffers rest on unenforced single-core discipline | **bajo** |
| F10 | `sshd.rs:303-306`, `:386-390` | X25519 session secret + KEX cookie from best-effort boot entropy | **bajo** (tracked: entropy milestone) |
| F11 | `sshd.rs:547-556` | `PK_OK` probes are not counted against `AUTH_ATTEMPTS_MAX` | **bajo** |

No **crítico** and no auth *fail-open* was found: every authentication decision
(`none` → FAILURE, wrong key → FAILURE, probe → PK_OK only for the authorized
key, signed request → ed25519 verify over `string session_id ‖ request`) fails
closed, and `service`/`method`/`algorithm` are all checked before the decision.

---

## F1 — No overall session deadline: remote unauthenticated wedge of the boot path (**alto**, **FIXED** — absolute `SESSION_DEADLINE_MS` in every receive + `duplicate SERVICE_REQUEST` guard + `CHANNEL_TOLERANCE_MAX` counters in both channel loops)

- **Where:** `kernel/src/sshd.rs:506-563` (pre-auth loop), `:717-774`
  (pre-exec loop), `:816-830` (close-wait loop); deadline constant
  `netstack.rs:45` (`OP_DEADLINE_MS = 10_000` = `STEP_DEADLINE_MS`, `sshd.rs:88`).
- **What's wrong:** every `wire.recv_into` has its own 10 s deadline, but each
  *loop* starts a fresh deadline per packet — there is no deadline for the
  session as a whole, and three loops accept a non-progress message forever:
  - pre-auth (`:506`): a **repeat** `SSH_MSG_SERVICE_REQUEST` re-enters the arm
    at `:513-542` unconditionally (`service_accepted` is set, never checked on
    re-entry) and is answered again — no counter, no state guard;
  - pre-exec (`:748`): `CHANNEL_WINDOW_ADJUST`/`CHANNEL_EOF` are swallowed in
    an unbounded loop;
  - close-wait (`:822-823`): same two messages keep the loop alive while the
    client withholds `CHANNEL_CLOSE`.

  An attacker needs **no credentials**: complete banner → KEXINIT → KEXDH_INIT
  → NEWKEYS (all unauthenticated), then send one `SERVICE_REQUEST` every <10 s
  forever. `serve_once` runs **synchronously in the boot chain**
  (`main.rs:279`, `hwtest.rs:60`), so boot never proceeds past it. (The
  accept/close wait loops `:200-218`/`:270-279` are additionally busy-spins —
  by design pre-scheduler, documented at `sshd.rs:56-58`, but they compound the
  stall.)
- **Severity:** **alto** — remote, unauthenticated, indefinite denial of boot;
  confidentiality/integrity untouched.
- **Reproduce:** `cargo xtask run` (or smoke-ssh's VM1), then from the host:
  connect to the forwarded `:2222`, run a normal banner+KEX+NEWKEYS exchange,
  and answer every `SERVICE_ACCEPT` with another `SSH_MSG_SERVICE_REQUEST`
  every 5 s. The server logs `sshd: …` each time and never reaches
  `SSHD_SESSION_OK`/the next boot stage; observe `main` stuck in `serve_once`.
- **Suggested fix:** one absolute session deadline (`accept_time +
  SESSION_DEADLINE_MS`, e.g. 120 s) checked inside `Conn::recv` and the
  plaintext recv helpers; plus message counters — max 1 `SERVICE_REQUEST`
  before auth, max N (`e.g. 64`) `WINDOW_ADJUST`/`EOF` in the two channel
  loops — each violation an `Err` (drop) with a bounded reason.

## F2 — Session-error path never closes the socket (**medio**, **FIXED** — the `Err` arm `abort()`s the socket before returning; also closed the pcap symptom class)

- **Where:** `kernel/src/sshd.rs:254-258` (`Err` arm returns) vs. the orderly
  close at `:263-279` (only reached from the `Ok` arm).
- **What's wrong:** when `session` fails, `serve_once` returns **before** the
  close block: no FIN/RST is sent (the peer sees a silent death — exactly the
  "desconexión sin razón" class), and the smoltcp socket stays `Established`.
  The *next* `serve_once` call's window-0 accept loop (`:200-218`) treats
  `State::Established` as a fresh client (`:203`) and runs `session()` against
  the stale half-dead connection, burning a full 10 s `STEP_DEADLINE` in
  `send_all` before failing again — a real accept can be starved until that
  peer's state ages out.
- **Severity:** **medio** — protocol hygiene + stale-state confusion; no
  privilege gain.
- **Reproduce:** connect, send a malformed KEXINIT → log
  `sshd: connection dropped: malformed client KEXINIT`; capture shows no FIN.
  Call `serve_once` again (hwtest loop): it immediately logs
  `sshd: client connected` (no SYN) and stalls ~10 s in the banner send.
- **Suggested fix:** in the `Err` arm, `sock.close()` + bounded wait for
  `Closed|TimeWait` (reuse the `:269-279` block), *then* `return served`.

## F3 — Advertised `MAX_PACKET`/`CHANNEL_WINDOW` exceed what the receive path can hold (**medio**, **FIXED** for `MAX_PACKET` — now `PAYLOAD_CAP`; `CHANNEL_WINDOW` is flow-control credit, not a per-packet promise, and stays as advertised credit — it only gates how much the peer may pipeline, which our receive loop drains).

- **Where:** `kernel/src/sshd.rs:101-102` (`CHANNEL_WINDOW = 64 KiB`,
  `MAX_PACKET = 32 KiB`, advertised in `CHANNEL_OPEN_CONFIRMATION` at
  `:695-704`) vs. `:94` (`PAYLOAD_CAP = 1024`) and `:987-989`
  (`recv_into` → `Err("encrypted payload exceeds the copy buffer")`).
- **What's wrong:** the confirmation *promises* we accept 32 KiB channel-data
  packets, but every encrypted payload is copied through a 1024-byte buffer —
  any payload > 1024 kills the connection (`PAYLOAD_CAP` bounds before any
  parser runs, which is good, but the promise and the bound disagree). A
  legitimate client sending a long `USERAUTH_REQUEST` (user name ≳ 700 bytes)
  or any >1 KiB payload is dropped; the peer cannot know in advance. Same
  class for `CHANNEL_WINDOW`: we advertise 64 KiB of receive credit we never
  track.
- **Severity:** **medio** — fail-closed (never a buffer overrun), but an
  interop-visible promise violation and a free DoS lever (cheap packet >1024
  bytes ends the session — though F1 makes ending sessions less useful).
- **Reproduce:** complete the encrypted phase, then send an encrypted
  `SSH_MSG_USERAUTH_REQUEST` whose payload is 1025+ bytes (e.g. user name of
  1000 bytes): server logs `sshd: connection dropped: encrypted payload
  exceeds the copy buffer` instead of answering `USERAUTH_FAILURE`.
- **Suggested fix:** advertise `MAX_PACKET = PAYLOAD_CAP as u32` (1024) in the
  confirmation — or raise `PAYLOAD_CAP` to 4096 (fits `RX_CAP`) and keep 32
  KiB. Pick one; they must agree.

## F4 — No user binding: the authorized key authenticates as any user (**medio**, **FIXED** — `SERVER_USERS` allowlist [git, reemplazo, luis]; anything else gets USERAUTH_FAILURE)

- **Where:** `kernel/src/sshd.rs:595-615` (service checked, **user never
  compared to anything**; only sanitized for logging at `:611`), `:654-656`
  (success log), `:836-858` (`run_command` has no user context).
- **What's wrong:** authorization is "holds `/AUTH.KEY`'s key" with zero
  account binding — `USERAUTH_REQUEST` with user `root`, `sshd`, `nobody` … all
  return `USERAUTH_SUCCESS`. Today's single-key TOFU deployment makes the
  practical impact small, but this is a fail-open *authorization default* the
  shell/multi-user milestone would inherit: any future per-user policy
  (`disks`/`install` builtins, file access) would silently apply to every
  impersonated name.
- **Severity:** **medio** — policy gap, not a bypass of the key check itself.
- **Reproduce:** with the client key from `/AUTH.KEY`, send a signed
  `USERAUTH_REQUEST` with `user = "root"` → `SSH_MSG_USERAUTH_SUCCESS`,
  `sshd: user root: authenticated with publickey`.
- **Suggested fix:** pin the accepted user (a `const SERVER_USER: &[u8] =
  b"git"`-style check right after the service check at `:595`, error → drop or
  `USERAUTH_FAILURE`), and carry the authenticated name into `channel_phase`
  for the eventual shell.

## F5 — Unsupported channel request/type with payload → drop instead of failure reply (**bajo**)

- **Where:** `kernel/src/sshd.rs:726-732` (any `parse_channel_request` `Err` →
  disconnect), `:689-691` (non-`session` type → disconnect); root cause in
  `ssh-wire/src/lib.rs:2518-2527` (the command string is read only for
  `exec`, so any non-`exec` request *carrying arguments* ends as
  `TrailingGarbage`).
- **What's wrong:** RFC4254 §5.4 says a server that does not support a
  request replies `CHANNEL_FAILURE` when `want_reply`; RFC4254 §5.1 likewise
  wants `CHANNEL_OPEN_FAILURE` for a foreign channel type. We instead kill the
  connection — fail-closed (safe) but abrupt: `ssh -t` (`pty-req`), `env`,
  `subsystem`, `-X` (`x11-req`) all die mid-session. Evidence the intended
  path was never finished: `ChannelError::UnsupportedType`
  (`ssh-wire/src/lib.rs:2373`) is **never constructed anywhere** in the
  workspace.
- **Severity:** **bajo** — interop/RFC-compliance; the drop direction is the
  safe one.
- **Reproduce:** `ssh -tt -p 2222 <guest>` → server logs
  `sshd: malformed CHANNEL_REQUEST: TrailingGarbage` and drops; plain
  `ssh <guest> echo x` (the smoke path) is unaffected.
- **Suggested fix:** in `channel_phase`, pre-dispatch on
  `request_type != b"exec"` *before* the strict parse (parse only recipient +
  type + want_reply), reply `CHANNEL_FAILURE` when asked, and extend
  `ssh-wire::parse_channel_request` to either validate a small set of known
  non-exec shapes or return `UnsupportedType` for them (constructing the
  existing variant). Same treatment for a foreign `CHANNEL_OPEN` type →
  `CHANNEL_OPEN_FAILURE`.

## F6 — Client's `initial_window`/`max_packet` never validated or honored (**bajo**)

- **Where:** `kernel/src/sshd.rs:682-692` (only `sender_channel` is kept from
  `CHANNEL_OPEN`), `:695-704` (confirmation), `:793-812` (all sends ignore the
  peer's window/max_packet).
- **What's wrong:** RFC4254 §5.1: the data we send must fit the peer's
  `initial_window` and `max_packet`. We advertise ours (`:698-699`) but never
  read the client's (`open.initial_window`/`open.max_packet` are dropped). A
  hostile or constrained peer opening with `initial_window = 0` (or
  `max_packet = 64`) receives a window/max-packet violation on the exec output
  (~265 bytes) — a protocol violation *by us*, and a way to force our send
  path into one. (Related: the client's window is also the credit our own
  64 KiB `CHANNEL_WINDOW` pretends to track — see F3.)
- **Severity:** **bajo** — no memory-safety issue (all sends are ≤ 512-byte
  fixed buffers), RFC violation + peer-controlled disconnect shape.
- **Reproduce:** craft `CHANNEL_OPEN(session, sender=0, initial_window=0,
  max_packet=64)`; after auth the server sends `CHANNEL_DATA` anyway; OpenSSH
  client drops with a window violation.
- **Suggested fix:** validate at open time — refuse (drop, or
  `CHANNEL_OPEN_FAILURE`) when `initial_window < expected_output` or
  `max_packet < 300`; or track the window and cap the data packet.

## F7 — `SSH_MSG_IGNORE`/`DEBUG`/`UNIMPLEMENTED` are fatal (**bajo**, **FIXED** — consumed at all three dispatch points with a shared `NOISE_MAX` (32) budget; rekey KEXINIT answers `rekey not supported`)

- **Where:** `kernel/src/sshd.rs:558-561` (pre-auth `other => Err`),
  `:749-752` (pre-exec), `:820-824` (close-wait `_ => Err`).
- **What's wrong:** RFC4253 §6.1: implementations "**MUST be able to receive**"
  `SSH_MSG_IGNORE`(2), `SSH_MSG_DEBUG`(4) and `SSH_MSG_UNIMPLEMENTED`(3) at any
  time; OpenSSH emits `IGNORE` when it needs to pad, `DEBUG` under `-v`, and
  answers rekey attempts with its own flow. We drop the connection on any of
  them (and on any rekey `KEXINIT`). Fail-closed, but an interop trap for a
  verbose or padding-happy peer — and it overlaps F1: a client *cannot* wedge
  via IGNORE (it dies), which is the one silver lining.
- **Severity:** **bajo** — RFC compliance/interop; the failure direction is
  safe.
- **Reproduce:** after `NEWKEYS`, send payload `[2, 0,0,0,0]` →
  `sshd: unexpected message 2 before authentication` → dropped.
- **Suggested fix:** at each dispatch point, consume `IGNORE`/`DEBUG` (bounded
  counter, e.g. 32 per session, then fatal) and keep everything else fatal;
  answer a rekey `KEXINIT` with a clean "rekey not supported" drop reason.

## F8 — Previous session's failure reason replayed pre-auth as a banner (**bajo**)

- **Where:** `kernel/src/sshd.rs:530-541` (replay after `SERVICE_ACCEPT`),
  `:127-140` (`remember_fail`), `:143-158` (`take_fail`), `:254-258` (writer).
- **What's wrong:** any unauthenticated client that reaches the service
  request receives the *previous* session's internal drop reason
  (`malformed KEXDH_INIT`, `too many authentication failures`, …) as a
  `USERAUTH_BANNER`. The strings are ours and static (no wire bytes, no
  secrets — the log-line discipline holds), but this is unauthenticated
  disclosure of internal parser state (useful for fingerprinting which
  checks fired) and the one-shot reason is consumed by whichever client
  connects first (an attacker can both *read* and *clear* it).
- **Severity:** **bajo** — information disclosure only.
- **Reproduce:** session A dies with `malformed KEXDH_INIT`; session B (fresh
  key exchange, no auth) logs `sshd: replaying last failure as banner` and
  OpenSSH prints `malformed KEXDH_INIT` on stderr.
- **Suggested fix:** replay only after `USERAUTH_SUCCESS`, or keep it
  log-only; if the remote-diagnostic value is wanted pre-auth, restrict it to
  a fixed coarse vocabulary (e.g. `session timeout` / `protocol error`).

## F9 — `static mut` buffers rest on unenforced single-core discipline (**bajo**)

- **Where:** `kernel/src/sshd.rs:108` (`static mut RX`), `:122-123`
  (`static mut LAST_FAIL`/`LAST_FAIL_LEN`), `:296-297`
  (`unsafe { &mut *addr_of_mut!(RX) }`), `:132-139`/`:146-157` (raw
  `copy_nonoverlapping`/`from_raw_parts`).
- **What's wrong:** the SAFETY comments are accurate *today* (single core,
  `serve_once` is the only writer, IRQ0 never touches these — the `ssh::RX`
  idiom), but nothing enforces the invariant: a second core, an IRQ handler
  that calls `serve_once`, or an async task would turn it into silent UB. Also
  `remember_fail` truncates at `LAST_FAIL_CAP` byte-wise — fine for the
  current `&'static str` ASCII reasons, would split a multi-byte char if a
  reason ever became non-ASCII (the banner path would then emit invalid
  UTF-8 — `userauth_banner_payload` copies bytes, OpenSSH prints them raw).
- **Severity:** **bajo** — latent, documented, no current trigger.
- **Reproduce:** n/a (design-level); a `cargo geiger`/review grep shows the
  only `unsafe` in the module.
- **Suggested fix:** wrap the two statics in a newtype with a documented
  single-core `unsafe impl Sync` guard (or `RefCell`-style accessor) so a
  future re-entrancy fails at review time; keep reasons ASCII-only
  (`remember_fail` could `?`-replace non-ASCII like `ssh::sanitize` does).

## F10 — X25519 session secret and KEX cookie from best-effort boot entropy (**bajo**, tracked)

- **Where:** `kernel/src/sshd.rs:303-306` (cookie from `boot_entropy()`),
  `:386-390` (X25519 private key from `boot_entropy()`); source
  `entropy.rs:15-23` (documented limits: no RDRAND/RDSEED on the Core2 Duo
  T7400, `rdtsc` jitter only, one-shot pool, entropy "not quantified").
- **What's wrong:** the module already documents this as a known limit with a
  future entropy milestone, but the SSH server is the one consumer where a
  weak boot pool breaks **session forward secrecy** (an attacker who guesses
  the per-boot seed can derive the same X25519 secret and decrypt) rather
  than just a predictable ISN. `host_seed` (long-term key) comes from disk
  and is fine; the *ephemeral* half is the exposure.
- **Severity:** **bajo** today (pool absorbs NIC arrival jitter + IRQ0
  preemption before the network chain — see `entropy.rs` docs), raised to
  **alto** if the pool turns out near-constant on a given machine; that is
  exactly what the entropy milestone must measure.
- **Reproduce:** n/a without the entropy measurement milestone; a cheap
  upper bound: dump `boot_entropy()` across 20 boots (hwtest diag marker) and
  check for repeats/low Hamming distance.
- **Suggested fix:** with the entropy milestone — reseed the CSPRNG from
  interrupt/RTC jitter *before* listening, add an explicit
  `sshd`-session reseed, and consider mixing a per-connection RDRAND-less
  jitter sample (RTT of the peer's SYN) into the ephemeral secret.

## F11 — `PK_OK` probes are not counted against `AUTH_ATTEMPTS_MAX` (**bajo**, **FIXED** — `PROBES_MAX` (16) per session)

- **Where:** `kernel/src/sshd.rs:547-556` — only `AuthOutcome::Rejected`
  increments `failures`; `ProbeAccepted` (`:549`) loops with no bound.
- **What's wrong:** reaching `ProbeAccepted` requires the *authorized* key, so
  an outsider cannot exploit it — but an authorized-but-unauthenticated peer
  can keep the session alive indefinitely (compounding F1), and a future
  multi-key `authorized_keys` would expose unlimited free probes per key.
- **Severity:** **bajo** (needs the authorized key today).
- **Reproduce:** with the client key, send the same `publickey` probe
  (boolean FALSE) in a loop: every one is answered `PK_OK`, no failure is
  counted, the session never ends.
- **Suggested fix:** count probes toward a separate, larger cap (e.g. 16) or
  fold them into `failures`; the F1 session deadline covers the rest.

---

## ssh-wire hygiene (companion crate — checked, not modified beyond tests)

- **`unsafe`:** none. `ssh-wire/src/lib.rs:36` is `#![forbid(unsafe_code)]`;
  grep confirms no `unsafe` token in the crate outside that attribute/doc.
- **`unwrap`/`expect`/`panic` on network data:** none in shipped code. All 100
  matches in the file are inside `#[cfg(test)]` (source ends at line 2673;
  first test-only `expect` is line 2731). The one `unwrap_or` in shipped code
  (`decode_packet_block`, line 226) is a deliberate fail-closed fallback
  (`[0;4]` → `TooSmall`), not a panic.
- **Fail-closed errors:** every parser returns a typed `Err`/`None` and every
  length read goes through `Reader::take`'s `checked_add` + `get`
  (`ssh-wire/src/lib.rs:315-320`) — a lying `u32::MAX` is refused before any
  declared body byte. Verified by the new adversarial tests below.
- **`ChannelError::UnsupportedType` (`ssh-wire/src/lib.rs:2373`) is never
  constructed** anywhere in the workspace — dead variant; see F5 (the open
  parser deliberately surfaces the raw type for the caller to refuse; that
  design is sound, only the caller's *response* is the finding).
- **`base64_decode` accepts non-canonical trailing bits** (RFC4648 §3.5 says a
  decoder *MAY* reject them; ours does not). Not a bug — decoded bytes are all
  that any comparison uses — but pinned by a test so any future strictness
  change is deliberate.

## Tests added this milestone (adversarial gap-fill, `ssh-wire/src/lib.rs`)

| parser | new test | covers |
|--------|----------|--------|
| `parse_service_request` | `service_request_roundtrip_and_rejections` | **was untested**; empty, wrong msg, every truncation, u32::MAX length, overrun, trailing, non-printable name (opaque → caller checks) |
| `parse_kexdh_init` | `kexdh_init_refuses_truncation_giant_lengths_and_trailing_bytes` | empty, every truncation, u32::MAX (→ `BadPublicKey`, not waited), trailing |
| `parse_kexdh_reply` | `kexdh_reply_refuses_giant_declared_lengths` | the three *outer* string lengths lying as u32::MAX (K_S → Truncated, f → BadPublicKey, sig → Truncated) |
| `parse_userauth_failure`, `parse_userauth_pk_ok`, `parse_service_accept` | `auth_answers_refuse_giant_declared_lengths` | u32::MAX name/algorithm/blob lengths from header-only payloads |
| `parse_userauth_request` | `userauth_request_refuses_truncation_and_giant_lengths` | every truncation of probe/signed/none, empty, u32::MAX user length, empty user, bad boolean, wrong msg |
| `parse_channel_open`, `parse_channel_open_confirmation` | `channel_open_refuses_truncation_and_giant_lengths` | empty, every truncation, u32::MAX type length, wrong msg, raw foreign type surfaced |
| `parse_channel_request` | `channel_request_enforces_bounds_before_waiting` | empty, every truncation, u32::MAX type/cmd lengths (→ `BadCommand` before waiting), clen 0 / 256 / 257, bad boolean, non-exec bare vs with-args (`TrailingGarbage` pinned → audit F5) |
| `parse_channel_number`, `parse_channel_data`, `parse_channel_exit_status` | `channel_small_messages_refuse_truncation_and_trailing_bytes` | empty, every truncation, u32::MAX data length, wrong msg, bad boolean, trailing |
| S5 encoders (12) | `s5_encoders_refuse_a_one_byte_short_buffer` | exact size succeeds, size−1 → `None`, never a panic/partial frame |
| `parse_authorized_key` | `authorized_key_refuses_empty_and_oversized_input` | empty file, comments-only, no body, **oversized base64 body vs the 96-byte scratch buffer**, no trailing newline, non-printable comment (opaque) |
| `parse_seed_hex` | `seed_hex_refuses_empty_input` | raw empty + short input |
| `base64_decode` | `base64_decode_pins_non_canonical_trailing_bits_as_accepted` | RFC4648 §3.5 MAY-reject behavior pinned |

Pre-existing coverage kept (not duplicated): banner empty/truncation/255-bound/
non-printable/bad-CRLF, packet empty/truncation/padding/block-size/u32::MAX
lengths, KEXINIT every-truncation + hostile name-lists, EXT_INFO hostile counts,
blob truncation/u32::MAX, `EncryptedRx` full-buffer/MAC/padding refusals, KDF
input caps.

**Gates:** `cargo xtask check` green · `cargo test -p ssh-wire` → **83 passed,
0 failed** (71 before this milestone, +12).
