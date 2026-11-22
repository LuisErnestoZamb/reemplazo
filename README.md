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
| `git-pack/` | Packfile v2 reader: header, zlib streams, OFS/REF deltas, trailer + in-memory index, tree/commit parsing — host-tested |
| `git-store/` | Local git object store formats: loose objects (SHA-1 + zlib), tree/commit writers, the v2 index and refs/HEAD — `no_std`, `forbid(unsafe_code)`, 44 adversarial host tests |
| `rtc/` | CMOS clock decoding (BCD, 12/24 h, leap years, century plausibility) — host-tested |
| `pci/` | PCI enumeration and device IDs (e1000, sky2, AHCI class, …) |
| `ahci-wire/` | AHCI (SATA) wire logic: HBA/port registers, PxIS/PxTFD decode, H2D FIS, command-header/table/PRDT layouts, IDENTIFY + PRDT splitting — `no_std`, `forbid(unsafe_code)`, zero deps, 27 adversarial host tests |
| `xtask/` | Build/test orchestration (`cargo xtask …`) |
| `docs/` | Milestone research: hardware probes, crate evaluations, smoltcp/installer designs |
| `iso/` | Bootable ISO assembly |
| `tools/` | Docker image with grub + xorriso + qemu |

## Building and testing

```sh
cargo xtask check   # fmt + clippy (host and kernel target) + tests + cross-build
cargo xtask smoke   # build ISO, boot headless, assert serial markers in order
cargo xtask smoke-install  # two IDE disks (FAT16 source + blank target) + an AHCI copy of the source; assert BLK_OK + AHCI_OK + FAT_OK + FS_WRITE_OK + FS_TREE_OK + INST_OK + GIT_CHECKOUT_OK + GIT_STORE_OK + GIT_PUSH_OK + NETINST_OK
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
requires) — plus a **third** image, `disk-ahci.img` (a byte copy of the
source volume), attached through QEMU's AHCI controller
(`-device ich9-ahci,id=sata` + `-drive if=none,id=ahci0` +
`-device ide-hd,drive=ahci0,bus=sata.1`) — the MacBook ICH7's transport.
It asserts `BLK_OK` (the ATA PIO probe), `AHCI_OK` (the AHCI driver's
PCI probe → port bring-up → `IDENTIFY DEVICE` → LBA0 read → magic, on
the SATA path the legacy PIO driver cannot reach), `FAT_OK` — the
FAT mount plus a byte-exact `/README.TXT` read — `FS_WRITE_OK`: the
kernel *writes* `/RESULT.TXT`, re-mounts from scratch and reads it
back byte-exact (with `/README.TXT` re-checked for clobbering), `FS_TREE_OK`:
`fat::write_file_all` creates a three-directory LFN path and reads
it back after a fresh re-mount, and `INST_OK`: the install flow on the target — GPT written and re-read
(`gptwire`), p2 formatted FAT16 with the shared `fat::format_fat16`,
the payload copied from the source volume and read back byte-exact
after a fresh re-mount, `GIT_CHECKOUT_OK`: G3's fetch checks the
whole depth-1 tree out into the source volume (112 files / 53 dirs,
byte-exact re-reads), `GIT_STORE_OK`: G4's local store writes `.git` (loose zlib objects streamed one
at a time, the checksummed v2 index, the rebuilt trees compared byte-exact, one
local commit on the fetched head, `.git/shallow`) and a fresh re-mount re-reads
and re-hashes it all, `GIT_PUSH_OK`: G5's push builds a **v2 pack of full
(non-delta) objects** — the local commit, its 60 trees and 135 blobs, read back
from `.git/objects` one object at a time — sends the v0 receive-pack command
list (`<old> <new> refs/heads/main\0report-status` + flush + pack) to the
in-container smart-HTTP receive-pack mock on `10.0.2.2:8091` (advertisement on
`:8090`), and asserts the returned `unpack ok` / `ok refs/heads/main` report;
after QEMU exits xtask decodes the **captured upload** with `git-pack`, checks
it holds exactly the local commit's reachable graph (parent = `.git/shallow`),
and hands it to real host `git index-pack --strict` + `cat-file` + `ls-tree -r`,
and `NETINST_OK`: after the boot network
chain, the kernel fetches `payload.tar` (the built kernel + README)
from an in-container responder on `10.0.2.2:8080` **with its own
stack**, walks the ustar headers, reinstalls onto the target and reads
everything back byte-exact. When QEMU exits, xtask re-verifies
`target.img` on the host — GPT + FAT + the installed kernel byte-exact
against the built binary.

**The installed disk is bootable (I1b).** `xtask iso()` builds GRUB's
`boot.img` (512 B, from `grub-pc-bin`) and `core.img` with
`grub-mkimage -O i386-pc -p '(hd0,gpt2)/boot/grub' -c <early.cfg>` in
the tools image, and concatenates them as `boot.img ‖ core.img`; the
ISO config loads that blob and the kernel as multiboot2 modules
(`module2 … grubpayload`, `module2 /boot/kernel.elf payload`). The
kernel copies both modules into statics before the frame allocator
exists (`mbi::check_module` bounds-checks every range), and both install
paths end by writing `core.img` to p1 (`bios_grub`, block list
recomputed and patched) and `boot.img` to LBA0 (partition table
preserved, kernel LBA patched at `0x5c`, exactly `grub-setup`'s patch
set) — GRUB boot code last, as the commit point. The offline install
also writes `/KERNEL.ELF` from the `payload` module, so a disk installed
with no network still boots. After the host re-verify (which now also
compares LBA0/p1 against the ISO's GRUB artifact byte-for-byte),
`smoke-install` starts a **second QEMU with `target.img` alone** (no
ISO) and asserts the installed system's chain — `BOOT_OK → VGA_OK →
MEM_OK → ALLOC_OK → RTC_OK → PCI_OK → E1000_OK → SHELL_OK` within 45 s
(`SHELL_OK` implies every earlier fail-closed network/AI/browser phase
passed).


`cargo xtask smoke-ssh` is the **ssh server**'s end-to-end proof. It
runs two QEMUs in one container: the first boots with a FAT16 disk
carrying `/HOST.BIN` (a generated ed25519 host-key seed) and
`/AUTH.KEY` (the client key's `ssh-ed25519 <blob>` line), starts
`sshd` on guest `:2222` and prints `SSHD_LISTEN_OK` … `SSHD_SESSION_OK`;
the second boots with the matching `/CLIENT.BIN` seed and, after its
normal boot chain, dials `10.0.2.2:2222` — the first VM publishes its
guest `:2222` with QEMU's `hostfwd` on the container loopback, which is
exactly where slirp's gateway leads — authenticates with `publickey`,
execs `echo SSHD_EXEC_OK` and prints `SSHD_OK` + `SSHD_EXEC_OK`. Then
an **OpenSSH interop phase**: xtask `docker exec`s a *real* Debian
OpenSSH client (the tools image's `ssh`) inside that same container
against the same sshd, as the sshd's second connection, and requires
the exec output `INTEROP_OK` plus the kernel's `SSHD_INTEROP_OK`
marker — the regression net for the 2026-11-22 live-hardware finding
(OpenSSH got `Permission denied (publickey)` from our sshd while our
own client passed; root cause: the `publickey` signature covered a raw
session id where RFC4252 §7 requires `string session identifier`
— RFC4251 `uint32 length ‖ bytes` — and our client and server shared
the bug). One per-run `ssh-keygen` keypair feeds all of it: the
`/CLIENT.BIN` seed, the `/AUTH.KEY` line and the interop client's
`target/iso-root/interop_key` file (never printed, never committed),
and a disk without `/HOST.BIN`/`/AUTH.KEY` gets no listener at all —
the 30-marker `smoke` and `smoke-install` chains are untouched. The
peer is trusted on first use **for the session** (its key and
fingerprint are printed); a persisted `known_hosts` with change
detection is pending with the filesystem milestone.

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
- [x] git over HTTPS — smart-HTTP `ls-remote` advertisement (GIT_LSREMOTE_OK), depth-1 `fetch` via v0 `want`/`deepen 1`/`done` → `git-pack` decode → iterative tree walk (GIT_FETCH_OK), a **full-tree** checkout into FAT16 — directories, long names, every blob — with a re-mount read-back (GIT_CHECKOUT_OK, `smoke-install`), the **local object store**: loose objects for every fetched commit/tree/blob, refs/HEAD, the v2 index, rebuilt trees checked byte-exact, and one local commit on top of the fetched head, all proved from a fresh mount (GIT_STORE_OK, `smoke-install`), and **push**: a v2 pack of full (non-delta) objects written by `git-pack`'s new encoder from the on-disk store, the v0 `receive-pack` command list + `report-status` exchange against an in-container smart-HTTP mock, the host decoding the captured upload with `git-pack` **and** real `git index-pack --strict`/`cat-file`/`ls-tree -r` (GIT_PUSH_OK, `smoke-install`). Real GitHub push (credentials + TLS) and delta/side-band encoding remain open
- [x] Shell — serial-console REPL with minimal builtins (ping, resolve, netinfo, …)
- [x] Keyboard — polled i8042 + set-1 decode feeding the shell's line discipline (QEMU `sendkey` → `KEYBOARD_OK`; MacBook needs UHCI/HID)
- [x] SSH server (S5) — ed25519 host key + `authorized_keys` read from a FAT16 volume, listener on `:2222`, KEX as responder, encrypted `publickey` auth, one `session` channel with `exec`; `cargo xtask smoke-ssh` proves our client → our server across two QEMUs (`SSHD_OK` + `SSHD_EXEC_OK`) **and a real Debian OpenSSH client → our server** (`INTEROP_OK` + `SSHD_INTEROP_OK`), which caught and now guards the RFC4252 §7 session-id `string`-framing fix. Up to two sequential connections per boot (VM2's client, then the interop client); TOFU only for the harness peer. S4 (git-over-ssh's `git-upload-pack`) and a concurrent accept loop are still open.
- [ ] sky2 driver (real hardware only)
- [ ] git, ssh, browser, AI client + editor
- [ ] ISO installer + network installer
  - [x] Block layer: ATA PIO driver on the legacy IDE primary channel (`cargo xtask smoke-install` asserts `BLK_OK`) and an **AHCI (SATA) driver** — PCI class 01h/06h/01h, BAR5 ABAR MMIO, port bring-up with bounded ST/FRE handshakes, `IDENTIFY DEVICE`, LBA48 `READ/WRITE DMA EXT` with a scatter/gather PRDT over 4 KiB frames, one command in flight (`ahci-wire` + `kernel/src/ahci.rs`; `smoke-install` asserts `AHCI_OK` on a QEMU `ich9-ahci` disk, and AHCI is the automatic source when no IDE disk answers). Real-ICH7 validation, IRQ completion and NCQ remain
  - [x] Filesystem: FAT16 reader + writer + directories + LFN writes, `no_std` + `forbid(unsafe_code)` + zero deps (`smoke-install` asserts `FAT_OK`, `FS_WRITE_OK` — write + re-mount read-back — and `FS_TREE_OK` — nested mkdir + long-name write + re-mount read-back; `fat/` crate, 102 adversarial host tests incl. randomized write/tree oracles)
  - [x] Shared FAT16 formatter: `fat::format_fat16` derives the geometry from the device size and self-checks against the reader — used by xtask's disk images *and* the kernel installer (`fat/tests/format.rs`, +8 tests)
  - [x] GPT reader + writer: `gptwire` crate, `no_std` + `forbid(unsafe_code)` + zero deps, 49 adversarial host tests (CRC32 vectors, truncated/bad-CRC headers, absurd entry counts, backup mismatch, overlap, MBR garbage)
  - [x] Install-to-disk (I1): GPT → FAT16 p2 → payload copy → byte-exact re-read (`smoke-install` asserts `INST_OK`; host-side re-verify after QEMU exits)
  - [x] Network installer (I2): `payload.tar` (ustar: built kernel + README) fetched from an in-container HTTP responder over the OS's own smoltcp/`net::http` stack, ustar walked with checksum validation, installed + byte-exact re-read (`smoke-install` asserts `NETINST_OK`; host verifies the installed kernel against the built binary). Real-`api.github.com` fetch and HTTPS remain later milestones
  - [x] **Bootable target (I1b)**: GRUB `boot.img`+`core.img` built by `grub-mkimage` at ISO time, shipped as a multiboot2 module, written by the installer to LBA0 + the `bios_grub` partition with `grub-setup`'s LBA patch and the GPT protective MBR preserved; `smoke-install` boots `target.img` **alone** (no ISO) and asserts the installed system's `BOOT_OK … SHELL_OK`. GRUB boot code on real-hardware disks (AHCI install write path) and a p2 `grub.cfg`/menu remain later work

## License

Copyright © 2026 **Arepitas Technologies Inc**

Licensed under the [GNU Affero General Public License v3.0](LICENSE)
(AGPL-3.0). Versions committed up to `580f394` were released under the
MIT license (still visible in the git history); from this commit the
project is AGPL-3.0 — free to use, modify and serve, provided you
publish your modifications. **Commercial licensing (perpetual, for
closed-source use) from Arepitas Technologies Inc.**
