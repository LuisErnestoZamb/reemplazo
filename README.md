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
| `bootinfo/` | Boot information parsing (multiboot2) |
| `net/` | Wire-protocol logic (Ethernet→TCP frames, DNS, DHCP) + HTTP/1.1 responses on `httparse` — host-tested |
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
cargo xtask run     # interactive boot in QEMU (Ctrl-C quits)
cargo test -p bootinfo <name>   # single test
```

The smoke test asserts each milestone's serial marker within 30 s:

```
BOOT_OK → MEM_OK → RTC_OK → PCI_OK → E1000_OK → NET_OK → PING_OK → DHCP_OK → DNS_OK → TCP_OK → TLS_OK → HTTP_OK → INT_OK → SHELL_OK
```

**Notes:**

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
- [x] e1000 driver — PCI probe, BAR decode, MMIO, MAC from EEPROM
- [x] e1000 TX/RX rings + ARP roundtrip
- [x] IPv4 + ICMP echo — ping roundtrip with checksum validation
- [x] DHCP client, DNS resolver, TCP client — github.com over port 80
- [x] TLS 1.3 client — HTTPS against github.com:443, pinned root certificate
- [x] HTTP/1.1 client — `httparse` head + RFC 9112 body framing (HTTP_OK)
- [x] Shell — serial-console REPL with minimal builtins (ping, resolve, netinfo, …)
- [ ] sky2 driver (real hardware only)
- [ ] git, ssh, browser, AI client + editor
- [ ] ISO installer + network installer

## License

Licensed under the [MIT License](LICENSE).
