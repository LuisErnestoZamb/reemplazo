# AGENTS.md

## What this is

- From-scratch OS written in **Rust** for a 2007 MacBook2,1 (hardware below). You are establishing structure, build, and test conventions; document them here as they land.
- Required deliverables, all in Rust in this workspace: kernel + low-level OS services, a command line (shell with **minimal builtins only** — not BusyBox/GNU/FreeBSD parity; grow on demand), an **opencode-like AI client with a VSCode-like editor**, a browser, **git** (clone/commit/fetch/push vs GitHub over ssh or https), **ssh client + server**, and an **installer**: bootable ISO **plus a network installer** (fetch the system over the network with the OS's own stack — sky2, DHCP, DNS, TCP/TLS).
- Dev happens on the **modern Mac (this checkout)**; the 2007 MacBook is the *target*, cross-compiled for. (opencode itself cannot run on the target — that's the point of the project.)

## Target hardware — hard constraints

- **CPU:** Core2 Duo T7400 (Merom, family 6 model 15), 2C/2T @ 2.16 GHz, x86-64 + VT-x, 4 MB L2.
- **ISA ceiling: SSSE3.** No SSE4.1, no SSE4.2, no POPCNT, no AVX → baseline is **x86-64-v1**. This is the single most important constraint in the repo.
- **RAM:** 2.9 GB DDR2-667 (2 slots, 4 GB max).
- **Disk:** 120 GB SATA 5400 rpm — the bottleneck. Budget runtime I/O accordingly.
- **Boot:** 32-bit Apple EFI running BIOS emulation → **GPT + `bios_grub` + GRUB i386-pc**. No macOS on disk; current Debian 13 install (~450 MB idle, IceWM + lightDM) is what this OS replaces.
- **Peripherals** (verified working under Debian — use these as hardware IDs when writing drivers):
  - GPU: Intel GMA950 (Xorg `intel`), 13.3" 1280x800
  - NIC: Marvell 88E8053 GbE (`sky2`) — wired + DHCP is the reliable dev path
  - WiFi: Atheros AR5418 a/bgn (`ath9k`) — radio OK, no credentials configured yet
  - Audio: HDA (`PipeWire` on Debian) · SMC/fan: `applesmc` + `coretemp`
  - DVD SuperDrive boots ISOs via **Option/C** — the primary way to test on real hardware
  - Bluetooth: present, disabled
- Network dev split (from the QEMU smoke scan): QEMU's NIC is **e1000** (`8086:100e`) — develop the TCP/IP stack against it; the MacBook's **sky2** (Marvell 88E8053, `11ab:4362`, constant `pci::SKY2_88E8053`) is *not* in QEMU, so the sky2 driver can only be validated on real hardware.

## Mistakes to avoid

- **Never build with `-C target-cpu=native`** or any host-feature detection: the build host is a modern Mac, the target is a T7400. Native code will emit SSE4+/AVX and die with SIGILL on the target. Pin the baseline explicitly (x86-64-v1 / no SSE4+ flags) and prefer `x86_64-unknown-none` (rustup-installable, `no_std`) over ad-hoc targets.
- **Don't plan an x86_64 UEFI bootloader or ESP.** Firmware is 32-bit EFI in BIOS-emulation mode; the boot chain is GRUB i386-pc → kernel. `x86_64-unknown-uefi` is the wrong path.
- **Don't assume headroom.** 2.9 GB RAM and a 5400 rpm disk rule out heavyweight runtimes, large indexes, and chatty logging at rest.
- **Networking is on the early critical path** (not "later"): clone/push vs GitHub, sshd, and the network installer all need sky2 → DHCP → DNS → TCP/IP → TLS 1.2+ / ssh (GitHub rejects legacy sha1 ssh-rsa). Prioritize the network stack accordingly.

## Workflow

- Git: branch `main`, remote `git@github.com:LuisErnestoZamb/reemplazo.git`. Commits: conventional (`feat:`, `fix:`, `docs:`, `build:`), one milestone per commit, message records what was actually verified.
- **Before every commit:** `cargo xtask check` (fmt + clippy for host crates *and* kernel target + host tests + kernel cross-build). Kernel is never linted/tested for the host — it is `x86_64-unknown-none` only.
- **Boot smoke test:** `cargo xtask smoke` — builds the ISO, boots it headless, asserts each milestone's serial marker in order (`BOOT_OK → MEM_OK → RTC_OK → PCI_OK → E1000_OK → NET_OK → PING_OK → DHCP_OK → DNS_OK → TCP_OK → TLS_OK → HTTP_OK → INT_OK → SHELL_OK`) within 30s. This is the test that catches broken boot (header/trampoline/paging/mbi), frame-allocator, CMOS RTC, PCI-scan, e1000-driver, network-path, DHCP/DNS/TCP-client, TLS/HTTP-client, interrupt (IDT/PIC/PIT), or serial-shell code. QEMU runs with user-mode networking (`slirp`: guest 10.0.2.15, gateway 10.0.2.2, DNS 10.0.2.3 — constants in the `net` crate, asserted by the DHCP client). `DNS_OK`, `TCP_OK` and `TLS_OK` need working outbound network through Docker's resolver (they resolve and fetch `github.com`), so the smoke test needs network access.
- Interactive boot: `cargo xtask run` (Ctrl-C quits; stale VM containers are force-cleaned on next run) drops into the serial shell — type `help`. Local terminals line-buffer, so for live echo run `stty raw -echo` in the terminal first.
- Single test: `cargo test -p mbi <name>`.
- Toolchain quirk (macOS 13, verified): no native `grub-mkrescue`, and Homebrew **cannot** build QEMU (Tier 3 → source build fails). Everything runs in the `reemplazo-tools` image (`tools/Dockerfile`: grub + xorriso + qemu); xtask prefers a host `qemu-system-x86_64` if one ever exists. Docker daemon must be running.
- `kernel` never builds with bare `cargo build` (excluded via `default-members`); it is built via `cargo xtask build` with `--target x86_64-unknown-none`.
- Verify against QEMU first; validate on real hardware via Option/C DVD or USB boot.
