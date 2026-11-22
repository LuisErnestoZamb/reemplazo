# reemplazo

**A from-scratch operating system in Rust for a 2007 MacBook2,1.**

*reemplazo* (Spanish for "replacement") is an operating system written from zero —
kernel, userspace, network stack, and applications — that replaces the Debian 13
install currently living on a 2007 MacBook. The goal is not to mimic a modern
distribution, but to prove that a single, focused Rust codebase can take aging
hardware from power-on to a usable, network-connected developer machine.

## Why

- **The machine deserves a second life.** A Core2 Duo MacBook with 2.9 GB of RAM
  is perfectly capable of terminal work, browsing, and version control — but every
  modern OS has dropped it. Rather than fight a shrinking Debian package set, we
  build exactly what the hardware needs and nothing more.
- **Everything in one language.** Kernel, shell, git, ssh, browser, and an
  AI-assisted editor are all implemented in Rust in this single workspace. No
  C toolchain, no out-of-tree modules, one set of conventions to learn.
- **Small by construction.** The hard limits of the target (no SSE4+, 2.9 GB RAM,
  5400 rpm disk) force lean data structures, zero-copy networking, and honest
  budgeting of I/O — habits that keep the system fast even on modern machines.
- **An AI client that runs where the AI isn't.** The flagship application is an
  opencode-like AI client with a VSCode-like editor. It is developed on a modern
  Mac and cross-compiled to run on hardware that could never host the original
  tooling — that gap *is* the point of the project.

## Target hardware

| Component | Device | Constraint |
|---|---|---|
| CPU | Core2 Duo T7400 (Merom), 2C/2T @ 2.16 GHz | ISA ceiling **SSSE3** → baseline **x86-64-v1** (no SSE4.1/4.2, no POPCNT, no AVX) |
| RAM | 2.9 GB DDR2-667 | No heavyweight runtimes, large indexes, or chatty logging |
| Disk | 120 GB SATA, 5400 rpm | The bottleneck — budget runtime I/O |
| Boot | 32-bit Apple EFI in BIOS emulation | GPT + `bios_grub` + GRUB i386-pc (**no UEFI/ESP**) |
| GPU | Intel GMA950, 13.3" 1280x800 | |
| NIC | Marvell 88E8053 GbE (`sky2`, `11ab:4362`) | Not present in QEMU — validate on real hardware |
| WiFi | Atheros AR5418 a/bgn (`ath9k`) | Radio OK, credentials pending |
| Audio / SMC | HDA · `applesmc` + `coretemp` | |
| Optical | DVD SuperDrive | Boots ISOs via **Option/C** — primary real-hardware test path |

Development happens on a **modern Mac**; the 2007 MacBook is the *target*,
cross-compiled for with a pinned Rust toolchain (`x86_64-unknown-none`).

## Deliverables

All in Rust, all in this workspace:

- **Kernel + low-level services** — boot (multiboot2 → long mode), memory
  management, interrupts (IDT/PIC/PIT), PCI enumeration, drivers.
- **Networking** — sky2/e1000 drivers → DHCP → DNS → TCP/IP → ICMP → TLS 1.3
  (certificate validation against a pinned root) → HTTP/1.1, and modern ssh
  (GitHub rejects legacy sha1 `ssh-rsa`).
- **Shell** — minimal builtins only; grows on demand (not BusyBox/GNU parity).
- **opencode-like AI client** with a VSCode-like editor.
- **Browser.**
- **git** — clone/commit/fetch/push against GitHub over ssh or https.
- **ssh** — both client and server.
- **Installer** — bootable ISO **plus** a network installer that fetches the
  system over the network using the OS's own stack.

## Repository layout

| Path | Crate / role |
|---|---|
| `kernel/` | The OS kernel — `no_std`, built only for `x86_64-unknown-none` |
| `mbi/` | Multiboot2 handoff range contract + hostile-input host tests |
| `net/` | HTTP/1.1 responses (`httparse` + RFC 9112 framing), SLIRP smoke constants, `parse_ipv4` — host-tested (the TCP/IP stack itself is smoltcp, see `docs/smoltcp-eval.md`) |
| `rtc/` | CMOS clock decoding (BCD, 12/24 h, leap years, century plausibility) — host-tested |
| `pci/` | PCI enumeration and device IDs (e1000, sky2, …) |
| `xtask/` | Build/test orchestration (`cargo xtask …`) |
| `docs/` | Milestone research: hardware probes, crate evaluations, smoltcp/installer designs |
| `iso/` | Bootable ISO assembly |
| `tools/` | Docker image with grub + xorriso + qemu |

## Building and testing

```sh
cargo xtask check   # fmt + clippy (host and kernel target) + tests + cross-build
cargo xtask smoke   # build ISO, boot headless, assert serial markers in order
cargo xtask smoke-install  # two IDE disks (FAT16 source + blank target); assert BLK_OK + FAT_OK + FS_WRITE_OK + FS_TREE_OK + INST_OK + GIT_CHECKOUT_OK + NETINST_OK
cargo xtask smoke-install  # same + FAT16 IDE disk; assert BLK_OK + FAT_OK + FS_WRITE_OK + GIT_CHECKOUT_OK
cargo xtask smoke-ssh  # two VMs: our sshd (one disk) ↔ our client (other disk) — SSHD_OK + SSHD_EXEC_OK
cargo xtask run     # interactive boot in QEMU (Ctrl-C quits)
cargo test -p mbi <name>   # single test
```

The smoke test asserts each milestone's serial marker in order — boot
markers within 30 s, then the keyboard phase within a further 15 s:

```
BOOT_OK → VGA_OK → MEM_OK → ALLOC_OK → RTC_OK → PCI_OK → USB_KBD_OK → E1000_OK → NET_OK → PING_OK → DHCP_OK → DNS_OK → TCP_OK → TLS_OK → HTTP_OK → GIT_LSREMOTE_OK → GIT_FETCH_OK → SSH_KEXINIT_OK → SSH_KEX_OK → INT_OK → TUI_OK → EDITOR_OK → AI_CHAT_OK → BROWSER_FETCH_OK → AI_EDIT_OK → BROWSER_RENDER_OK → BROWSER_CSS_OK → BROWSER_NAV_OK → SHELL_OK → KEYBOARD_OK
```

`KEYBOARD_OK` is the keyboard milestone's end-to-end proof: after
`SHELL_OK`, xtask connects to QEMU's HMP monitor and *types*
`echo KEYBOARD_OK` with `sendkey`; the marker must be the line the
shell's `echo` builtin printed (an exact match — the keystroke echo
alone does not count), proving i8042 → scancode decode → line
discipline → builtin.
`cargo xtask smoke-install` boots the same ISO with **two** 64 MiB IDE
disks attached — a FAT16 *source* volume (`disk.img`) and a blank
*target* (`target.img`, carrying the wipe marker the installer
requires) — and asserts `BLK_OK` (the ATA PIO probe), `FAT_OK` — the
FAT mount plus a byte-exact `/README.TXT` read — `FS_WRITE_OK`: the
kernel *writes* `/RESULT.TXT`, re-mounts from scratch and reads it
back byte-exact (with `/README.TXT` re-checked for clobbering), `FS_TREE_OK`:
`fat::write_file_all` creates a three-directory LFN path and reads
it back after a fresh re-mount, and `INST_OK`: the install flow on the target — GPT written and re-read
(`gptwire`), p2 formatted FAT16 with the shared `fat::format_fat16`,
the payload copied from the source volume and read back byte-exact
after a fresh re-mount, `GIT_CHECKOUT_OK`: G3's fetch checks the
whole depth-1 tree out into the source volume (112 files / 53 dirs,
byte-exact re-reads), and `NETINST_OK`: after the boot network
chain, the kernel fetches `payload.tar` (the built kernel + README)
from an in-container responder on `10.0.2.2:8080` **with its own
stack**, walks the ustar headers, reinstalls onto the target and reads
everything back byte-exact. When QEMU exits, xtask re-verifies
`target.img` on the host — GPT + FAT + the installed kernel byte-exact
against the built binary.


`cargo xtask smoke-ssh` is the **ssh server**'s end-to-end proof. It
runs two QEMUs in one container: the first boots with a FAT16 disk
carrying `/HOST.BIN` (a generated ed25519 host-key seed) and
`/AUTH.KEY` (the client key's `ssh-ed25519 <blob>` line), starts
`sshd` on guest `:2222` and prints `SSHD_LISTEN_OK` … `SSHD_SESSION_OK`;
the second boots with the matching `/CLIENT.BIN` seed and, after its
normal boot chain, dials `10.0.2.2:2222` — the first VM publishes its
guest `:2222` with QEMU's `hostfwd` on the container loopback, which is
exactly where slirp's gateway leads — authenticates with `publickey`,
execs `echo SSHD_EXEC_OK` and prints `SSHD_OK` + `SSHD_EXEC_OK`. The
keypair is generated per run into those two disk images only (never
printed, never committed), and a disk without `/HOST.BIN`/`/AUTH.KEY`
gets no listener at all — the 29-marker `smoke` and `smoke-install`
chains are untouched. The peer is trusted on first use **for the
session** (its key and fingerprint are printed); a persisted
`known_hosts` with change detection is pending with the filesystem
milestone.

**Notes:**

- The kernel heap (`ALLOC_OK`) is a 16 MiB contiguous run carved from the
  frame allocator at boot (`linked_list_allocator` behind an IRQ-aware
  lock — see `kernel/src/heap.rs`). Interrupt handlers must never
  allocate; a failed allocation panics and halts (no OOM recovery).

- `kernel` never builds with bare `cargo build` (excluded via `default-members`);
  it is built via `cargo xtask build --target x86_64-unknown-none`.
- On macOS, `grub-mkrescue` and QEMU run inside the `reemplazo-tools` Docker
  image (`tools/Dockerfile`); the Docker daemon must be running.
- Never build with `-C target-cpu=native`: the host is modern, the target is a
  T7400 — native code would emit SSE4+/AVX and die with SIGILL on the MacBook.
- Verify against QEMU first; validate on real hardware via Option/C DVD or USB.
- `cargo xtask run` boots into the serial shell (`reemplazo>` prompt — type
  `help`). For live echo, run `stty raw -echo` first: the local terminal
  otherwise line-buffers input and echoes it in addition to the shell.
- **AI client:** `ai <message>` posts to the in-container mock (or, once
  `ai endpoint <https-url>` is set, over TLS to that endpoint with `stream:
  true` and a live SSE pane); `ai model <name>`, `ai key <token>` (RAM only —
  never printed, though the shell echoes the typed line), `ai config`,
  `ai stream <message>` (keyless SSE demo against the mock) and `ai apply`
  (editor integration).
- **Keyboard input:** besides the serial console, the shell also reads QEMU's
  PS/2 keyboard (polled i8042 → set-1 decode → same line discipline — the
  MacBook's built-in keyboard is USB HID and needs the UHCI milestone).
  `cargo xtask run` prints the QEMU monitor address for key injection, e.g.
  `printf 'sendkey h\nsendkey i\nret\n' | nc 127.0.0.1 <port>` (letters are
  key names as-is, `spc` = space, `ret` = Enter, `shift-k` = uppercase K;
  `cargo xtask smoke` does the same automatically to assert `KEYBOARD_OK`).
- Dependencies follow the project policy: known, audited crates first
  (`embedded-tls`, `httparse`, `rand_chacha`, …), from-scratch only under the
  documented exceptions — see `.opencode/skills/rust-os-dev/SKILL.md` and the
  evaluations in `docs/`.

## Status

Milestones landed so far (see `git log` for details):

- [x] Cargo workspace with xtask orchestration
- [x] Multiboot2 boot milestone — GRUB → long mode, serial console
- [x] Interrupt milestone — IDT, PIC remap, PIT timer, exception dispatch
- [x] Frame allocator + PCI enumeration
- [x] CMOS RTC — boot clock, certificate dates validated against it (RTC_OK)
- [x] Kernel heap — `linked_list_allocator` (16 MiB contiguous carve), global `alloc` (`Vec` proof → `ALLOC_OK`)
- [x] e1000 driver — PCI probe, BAR decode, MMIO, MAC from EEPROM
- [x] e1000 TX/RX rings + ARP roundtrip
- [x] IPv4 + ICMP echo — ping roundtrip with checksum validation
- [x] DHCP client, DNS resolver, TCP client — github.com over port 80
- [x] TCP/IP stack migrated to **smoltcp** — hand-rolled frame/DHCP/DNS/TCP code replaced, ~2300 lines removed (docs/smoltcp-eval.md)
- [x] TLS 1.3 client — HTTPS against github.com:443, pinned root certificate
- [x] HTTP/1.1 client — `httparse` head + RFC 9112 body framing (HTTP_OK)
- [x] git over HTTPS — smart-HTTP `ls-remote` advertisement (GIT_LSREMOTE_OK), depth-1 `fetch` via v0 `want`/`deepen 1`/`done` → `git-pack` decode → iterative tree walk (GIT_FETCH_OK), and a **full-tree** checkout into FAT16 — directories, long names, every blob — with a re-mount read-back (GIT_CHECKOUT_OK, `smoke-install`)
- [x] Shell — serial-console REPL with minimal builtins (ping, resolve, netinfo, …)
- [x] Keyboard — polled i8042 + set-1 decode feeding the shell's line discipline (QEMU `sendkey` → `KEYBOARD_OK`; MacBook needs UHCI/HID)
- [x] SSH server (S5) — ed25519 host key + `authorized_keys` read from a FAT16 volume, listener on `:2222`, KEX as responder, encrypted `publickey` auth, one `session` channel with `exec`; `cargo xtask smoke-ssh` proves our client → our server across two QEMUs (`SSHD_OK` + `SSHD_EXEC_OK`). One connection per boot; TOFU only for the harness peer. S4 (git-over-ssh's `git-upload-pack`) and multi-connection accept are still open.
- [ ] sky2 driver (real hardware only)
- [ ] git, ssh, browser, AI client + editor
- [ ] ISO installer + network installer
  - [x] Block layer: ATA PIO driver on the legacy IDE primary channel (`cargo xtask smoke-install` asserts `BLK_OK`)
  - [x] Filesystem: FAT16 reader + writer + directories + LFN writes, `no_std` + `forbid(unsafe_code)` + zero deps (`smoke-install` asserts `FAT_OK`, `FS_WRITE_OK` — write + re-mount read-back — and `FS_TREE_OK` — nested mkdir + long-name write + re-mount read-back; `fat/` crate, 102 adversarial host tests incl. randomized write/tree oracles)
  - [x] Filesystem: FAT16 reader + writer, `no_std` + `forbid(unsafe_code)` + zero deps (`smoke-install` asserts `FAT_OK` then `FS_WRITE_OK` — write + re-mount read-back; `fat/` crate, 71 adversarial host tests incl. a randomized write oracle)
  - [x] Shared FAT16 formatter: `fat::format_fat16` derives the geometry from the device size and self-checks against the reader — used by xtask's disk images *and* the kernel installer (`fat/tests/format.rs`, +8 tests)
  - [x] GPT reader + writer: `gptwire` crate, `no_std` + `forbid(unsafe_code)` + zero deps, 49 adversarial host tests (CRC32 vectors, truncated/bad-CRC headers, absurd entry counts, backup mismatch, overlap, MBR garbage)
  - [x] Install-to-disk (I1): GPT → FAT16 p2 → payload copy → byte-exact re-read (`smoke-install` asserts `INST_OK`; host-side re-verify after QEMU exits). GRUB boot code on the target is deferred (I1b) — the installed disk is not yet bootable
  - [x] Network installer (I2): `payload.tar` (ustar: built kernel + README) fetched from an in-container HTTP responder over the OS's own smoltcp/`net::http` stack, ustar walked with checksum validation, installed + byte-exact re-read (`smoke-install` asserts `NETINST_OK`; host verifies the installed kernel against the built binary). Real-`api.github.com` fetch and HTTPS remain later milestones

## License

Copyright © 2026 **Arepitas Technologies Inc**

Licensed under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0). Versions committed up to `580f394` were released under the
MIT license (still visible in the git history); from this commit the
project is AGPL-3.0 — free to use, modify and serve, provided you
publish your modifications. **Commercial licensing (perpetual, for
closed-source use) from Arepitas Technologies Inc.**
