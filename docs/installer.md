# Installer design — bootable ISO + network installer

Status: design (research complete) + **FS1 landed** — read-only FAT16 and its `FAT_OK`
smoke marker (§8.1). Scope: the two installer deliverables from
AGENTS.md — *a bootable ISO* and *a network installer that fetches the system over the
network with the OS's own stack*. Target: 2007 MacBook2,1, GRUB i386-pc boot chain
(32-bit Apple EFI in BIOS emulation — **no UEFI, no ESP**, see AGENTS.md).

Everything marked *(verified …)* was checked in this checkout or against the live
network on 2026-11-21; everything else carries a source URL.

---

## 1. Current state (what exists today)

### 1.1 ISO pipeline

`cargo xtask iso` (`xtask/src/main.rs`, `iso()`):

1. cross-compiles `kernel` → `target/x86_64-unknown-none/release/kernel`
   (≈700 KB, *verified* by `ls`),
2. stages `target/iso-root/boot/kernel.elf` + `iso/boot/grub/grub.cfg`,
3. builds the `reemplazo-tools` image (`tools/Dockerfile`: Debian trixie-slim +
   `grub-common`, `grub-pc-bin`, `xorriso`, `mtools`, `dosfstools`, `qemu-system-x86`),
4. runs `grub-mkrescue -o /work/os.iso /work` in the container.

`iso/boot/grub/grub.cfg` is a single `menuentry "reemplazo"` with
`multiboot2 /boot/kernel.elf`, `timeout=0`. QEMU boots it headless
(`qemu_std_args`: `-m 256M -cdrom … -serial stdio -netdev user -device e1000,…`).

Container contents *verified* with `dpkg -L`:

- `grub-pc-bin` ships the full `i386-pc` module set **including** `boot.img`,
  `part_gpt.mod`, `part_msdos.mod`, `fat.mod`, `ext2.mod`, `multiboot2.mod`,
  `biosdisk.mod`, `search*.mod`, `normal.mod` — everything needed to build a
  *target-disk* `core.img` and to read our future filesystems from GRUB.
- `grub-common` ships `grub-mkimage`, `grub-mkrescue`.
- **`grub-install` is NOT installed** (`which grub-install` → missing; it lives in
  Debian's `grub2-common`, not in the image). This is fine — see §4: the installer OS
  itself performs the two writes `grub-install` would do, and `grub-mkimage` (present)
  builds `core.img` at ISO-build time.
- Host-side verification tools present: `mcopy`/`mdir` (mtools), `mkfs.vfat`,
  `fsck.fat`, `tar`, `sha256sum`. **`sfdisk`/`fdisk`/`gdisk` are absent** — the GPT
  sanity check must be done by xtask itself (§7) or by adding a package to the image.
- QEMU 10.0.13; device help lists `ide-hd`, `ich9-ahci` (alias `ahci`), `virtio-blk`.

### 1.2 Network stack capabilities (verified by reading the code)

- Boot-time chain in `kernel/src/main.rs`: e1000 probe → DHCP → DNS (`github.com`) →
  plain HTTP GET (`tcp::http_smoke`) → HTTPS GET (`tls::https_smoke`) → shell.
  The smoke test (`xtask smoke`) asserts the 14 markers
  `BOOT_OK → MEM_OK → RTC_OK → PCI_OK → E1000_OK → NET_OK → PING_OK → DHCP_OK →
  DNS_OK → TCP_OK → TLS_OK → HTTP_OK → INT_OK → SHELL_OK` in order.
- **TLS**: `kernel/src/tls.rs` — TLS 1.3 via `embedded-tls` (pinned rev) +
  `rustls-webpki`, **exactly one trust anchor**: `usertrust_ecc_ca.der`
  (SHA-256 `4ff460d5…`). Certificate dates come from the CMOS RTC and degrade to
  "not checked" if the clock is unavailable. A full handshake + HTTP GET against
  `github.com:443` works (`TLS_OK`).
- **HTTP response handling exists and is host-tested**: `net/src/http.rs`
  (`ResponseParser`, on top of the `no_std` `httparse` crate) parses the head
  (8 KiB cap) and frames bodies per RFC 9112 §6.3 — `Content-Length`, `chunked`
  (strict CRLF, extensions/trailers), close-delimited, and no-body statuses — with
  the smuggling defenses (TE wins over CL, duplicate CL refused, undecodable codings
  fail closed). The API is **incremental**: `feed(&input, &mut body_out)` returns
  `{body, complete}` per call, which is exactly the shape a disk-writing sink needs.
  `tls::https_smoke` already drives it (`HTTP_OK` marker), but caps the body at
  64 KiB (`READ_CAP`) and keeps only a 512 B prefix. The plain-HTTP smoke
  (`tcp::http_smoke`) is still the older one-shot fixed-buffer read.
- **What the installer's download path still needs**: a reusable `http_get(url,
  sink)` abstraction (plain `Conn` and `tls::Socket`), redirect (`Location`)
  following, `Range` (optional), and lifting the smoke's byte caps. The transports
  *can* stream: `tls::Socket` implements `embedded_io::Read` with a sliding window
  (`Conn::release`), so this is new glue, not a new transport.
- **TCP**: one outstanding segment, poll-based retransmit (3 attempts), no congestion
  control — fine for a ≤100 MB payload on a LAN/DSL path (1460 B per RTT), documented
  as a limit.
- **Shell** (`kernel/src/shell.rs`): line-edited serial REPL, builtins grown on demand
  (`ping`, `resolve`, …). This is the natural installer UX; automated runs can drive it
  by writing to QEMU's stdin.
- **Memory**: frame allocator + selftest (`memory::init`), **no heap**. TLS record
  buffers already live in `static`s — the same pattern applies to download buffers.
- **No block/disk code exists anywhere** (*verified* by grep over all `*.rs`: no
  ATA/AHCI/IDE/partition/FS code). Every disk-related item below is new work.
- The `multiboot2` crate parses MBI tags but our kernel currently uses only
  `bootloader_name`/mmap/framebuffer —
  **no cmdline and no multiboot2 module tags yet** (small, bounded additions).

### 1.3 Certificates on the hosts we may fetch from *(verified with `openssl s_client`)*

| Host | Chain (leaf → … → root) | Accepted by our TLS client? |
|---|---|---|
| `github.com` | Sectigo DV E36 → Sectigo Root E46 → **USERTrust ECC** | ✅ (smoke passes) |
| `api.github.com` | `*.github.com` Sectigo → **USERTrust ECC** | ✅ |
| `codeload.github.com` | Sectigo → **USERTrust ECC** | ✅ |
| `raw.githubusercontent.com`, `release-assets.githubusercontent.com` (where release downloads redirect) | Let's Encrypt `YR1` → ISRG Root YR → **ISRG Root X1** | ❌ rejected (single pinned anchor) |

This constrains URL choice more than anything else (§5).

---

## 2. What the installer ISO needs beyond the current live ISO

1. **(a) kernel + init payload** — ours is one kernel ELF; the installable system is
   shipped as a single artifact `payload.tar` (§4.1) which GRUB loads as a
   **multiboot2 module** so the installer never needs an ISO9660 reader:
   ```
   menuentry "install" {
       multiboot2 /boot/kernel.elf
       module2    /boot/payload.tar payload
       boot
   }
   menuentry "live" { multiboot2 /boot/kernel.elf; boot }
   ```
   The kernel reads `info.command_line_tag()` / `info.module_tags()`;
   the tar is walked in memory.
2. **(b) target-disk selection** — needs the block driver (§3), a `disks` listing
   builtin, and an explicit typed confirmation before anything is written (serial UX,
   `kernel/src/shell.rs` style).
3. **(c) partitioning/formatting** — implemented in the installer itself (§3, §4):
   a GPT writer + a FAT32 formatter. No external tools exist on the target (there is
   no userspace yet), and the container doesn't even have `sfdisk` — so "the OS
   partitions itself" is not a shortcut, it is the only option.

The ISO additionally carries the GRUB-install artifacts the installer writes to disk:
`/boot/grub/boot.img` (copied from `grub-pc-bin`) and `/boot/grub/core.img`
(**generated during `xtask iso`** with `grub-mkimage` inside the container, §4.2).

---

## 3. Block layer & partition table

### 3.1 Drivers

| Where | Controller | First implementation |
|---|---|---|
| QEMU smoke (`-drive …,if=ide`) | PIIX3 IDE (`ide-hd`) | **PIO-mode ATA** — trivial (port I/O, IDENTIFY, READ/WRITE SECTOR), enough for installer milestones; DMA later if throughput matters |
| MacBook2,1 (real HW) | Intel ICH7-M SATA **AHCI**, PCI `8086:27c5` (*verified*: [linux-hardware probe](https://linux-hardware.org/?log=hwinfo&probe=61f09eb46a) shows `82801GBM/GHM (ICH7-M Family) SATA Controller [AHCI mode]` prog-if 01, driver `ahci` works) | AHCI driver (port init, FIS-based command slots) — [osdev AHCI](https://wiki.osdev.org/AHCI) is the reference |

Sequencing rationale: QEMU's `pc` machine defaults to PIIX IDE, so the *installer*
milestones run against IDE; the AHCI driver is only required for the final
real-hardware validation (milestone 10). If desired, `ich9-ahci` (alias `ahci`) is also
available as a PCI device in the container's QEMU 10.0.13 *(verified with
`-device help`)* for an intermediate AHCI-in-QEMU test.

### 3.2 MBR vs GPT — recommendation: **GPT + `bios_grub` partition**

- AGENTS.md already fixes the boot chain as *GPT + bios_grub + GRUB i386-pc* (that is
  what Debian used on this machine), and the GRUB manual documents exactly this
  BIOS-on-GPT path: a whole partition reserved for GRUB, "without the risk of being
  overwritten by other software" — [GRUB manual §BIOS installation](https://www.gnu.org/software/grub/manual/grub/html_node/BIOS-installation.html).
- GPT costs us: protective MBR, header + entries with CRC32, backup header at last
  LBA (a ~20-line table-driven CRC32 — we have no CRC32 today, only the internet
  checksum). Well specified: [osdev GPT](https://wiki.osdev.org/GPT).
- MBR would be simpler (no CRC) and is capped at 2 TiB (irrelevant: 120 GB disk), and
  the GRUB manual *recommends* embedding `core.img` in the MBR gap with the first
  partition ≥1 MiB. We keep MBR as a documented fallback (the writer is
  partition-table-agnostic above the `bios_grub`/gap decision), but default to GPT to
  match AGENTS.md and the machine's existing layout.
- **Layout written by the installer** (120 GB disk, 512 B sectors):

  | # | Type | Size | Contents |
  |---|---|---|---|
  | — | GPT header/entries + backup | LBA0 protective MBR, LBA1 header, LBA2.. entries, backup at end | CRC32-protected |
  | p1 | `bios_grub` (EF02, GUID `21686148-6449-6e6f-744e-656564454649`) | 1 MiB @ 1 MiB | `core.img` (≈172 KB, §4.2) |
  | p2 | Microsoft Basic Data (or EFI System — GRUB doesn't care, but Basic Data is honest here) | rest of disk, 1 MiB-aligned | FAT32 volume (§4.3) |

---

## 4. GRUB installation on the target disk (no `grub-install` available)

Reference: [GRUB manual §BIOS installation](https://www.gnu.org/software/grub/manual/grub/html_node/BIOS-installation.html)
and the reference implementation `grub-bios-setup`
([source](https://git.savannah.gnu.org/cgit/grub.git/tree/util/grub-bios-setup.c),
boot code [boot.S](https://git.savannah.gnu.org/cgit/grub.git/tree/grub-core/boot/i386-pc/boot.S)).

Two artifacts, both produced **at ISO-build time**, shipped *on* the ISO:

1. **`core.img`** — built in the container during `xtask iso`:
   ```
   grub-mkimage -O i386-pc -o core.img \
       -p '(hd0,gpt2)/boot/grub' \
       normal multiboot2 part_gpt fat biosdisk search search_fs_file \
       search_label configfile echo terminal ls
   ```
   Measured sizes *(verified)*: full-ish set = **171 861 B**, minimal set
   (normal+multiboot2+fat+search) = **150 247 B** — both fit the 1 MiB `bios_grub`
   partition (GRUB manual: BIOS boot partition needs ≥31 KiB, 1 MiB recommended).
   Prefix robustness: bake `(hd0,gpt2)/boot/grub` (single-disk machines — the MacBook
   has exactly one disk) **and** pass an embedded early config
   (`grub-mkimage -c`) that re-resolves by label:
   ```
   search --label --set=root reemplazo
   set prefix=($root)/boot/grub
   normal
   ```
   so a changed BIOS drive order or `gpt1/gpt2` numbering self-heals.
2. **`boot.img`** — copied verbatim from `/usr/lib/grub/i386-pc/boot.img`
   (512 B, *verified present*).

**Installer write procedure** (new kernel code, the exact job of `grub-bios-setup`):

1. write `core.img` at the start of p1 (`bios_grub`);
2. patch `boot.img`'s blocklist field with p1's first sector (field defined in
   `boot.S` — read the byte offset from the pinned GRUB source when implementing,
   do not guess);
3. write `boot.img`'s boot-code area to LBA0 **preserving** bytes 446..510
   (the partition table) and 510..512 (`0x55AA`).

**Ordering = commit point:** files on p2 first, GRUB boot code *last*. A power cut
mid-install then leaves a disk that still contains whatever it had before (or nothing),
never a half-installed GRUB. Documented failure policy: re-run the installer.

Installed `/boot/grub/grub.cfg` (written from `payload.tar`):
```
set timeout=3
set default=0
menuentry "reemplazo" { multiboot2 /boot/kernel.elf; boot }
```
GRUB needs `multiboot2`, `part_gpt`, `fat`, `normal`, `search` — all present in
`grub-pc-bin` *(verified file list)*.

---

## 5. Filesystem recommendation: **FAT32 via the `fatfs` crate**

### 5.1 Candidates

| Option | no_std fit | License | Formatter | GRUB can boot it? | Notes |
|---|---|---|---|---|---|
| **FAT32 — [`fatfs`](https://crates.io/crates/fatfs)** ([repo](https://github.com/rafalh/rust-fatfs), [docs](https://docs.rs/fatfs/latest/fatfs/)) | ✅ README: “Basic no_std environment support”; `default-features = false` is explicitly the no_std mode; features `lfn`/`alloc`/`unicode` are opt-in, `alloc` only for `String` APIs | MIT | ✅ `fatfs::format_volume` | ✅ `fat.mod` in `grub-pc-bin` | Mature (0.3.6), FAT12/16/32 + LFN, `TimeProvider` hooks into our RTC. *Spike required:* prove it builds on `x86_64-unknown-none` without `alloc` over a block-device adapter implementing its Read/Write/Seek traits (§7, milestone 3) |
| ext2 — [`ext2`](https://crates.io/crates/ext2) | ❌ std/Unix-only: deps `libc`, `nix`, `lazy_static`; roadmap lists “no-std” as *future* work ([docs](https://docs.rs/ext2/latest/ext2/)) | MIT/Apache | ❌ | ✅ `ext2.mod` | Not usable from the kernel |
| ext2 — [`efs`](https://crates.io/crates/efs) ([repo](https://codeberg.org/RatCornu/efs)) | ✅ advertised no_std, provides `Ext2Fs` + POSIX-ish traits | **GPL-3.0** | ❌ (read/write fs, no mkfs) | ✅ | Usable technically; GPL would make the derived work GPL — wrong call for this repo unless we accept that. Also “early development … bugs are expected” per its own docs |
| Custom FS | ✅ by definition | — | — | ❌ **GRUB cannot read it** | Fatal flaw: GRUB i386-pc only boots from its supported FS modules; a custom FS forces the fragile “blocklist in filesystem” fallback the GRUB manual recommends against. Revisit only when GRUB is no longer the bootloader |

### 5.2 Decision

**FAT32 on p2, via `fatfs` (`default-features = false`, `lfn` on, `alloc` off), with
`format_volume` as the mkfs.** Reasons: the only candidate that is simultaneously
(a) proven no_std design, (b) permissively licensed, (c) has a built-in formatter,
(d) bootable by GRUB out of the box, (e) verifiable host-side with the mtools/dosfstools
already in the tools image. FAT's weaknesses (no permissions, 4 GiB files, no
journal) are irrelevant for a system partition holding a 700 KB kernel, and there is no
userspace yet that would notice. ext2 stays on the roadmap for when the OS needs
permissions — by then either `efs`'s license situation or a from-scratch ext2
(Ext2 structures are well documented, [osdev Ext2](https://wiki.osdev.org/Ext2)) can
be revisited deliberately.

---

## 6. Network installer design

### 6.1 Payload format

Single artifact **`payload.tar`** (POSIX **ustar**, [GNU tar manual](https://www.gnu.org/software/tar/manual/html_node/ustar.html)):

```
payload.tar
├── kernel.elf            # the kernel to install (≈700 KB)
├── grub/boot.img         # from grub-pc-bin
├── grub/core.img         # built by xtask iso (§4)
└── grub/grub.cfg         # installed menuentry
```

Why tar: trivially parseable **sequentially and without alloc** (512-byte headers,
known layout), created on the build side with plain `tar` (present in the container
*and* on macOS), and it keeps the network installer and the offline installer
identical downstream — both end with “walk `payload.tar` and write these files”.
An alternative custom 4-entry header table is a fallback if tar parsing surprises us;
gzip is deliberately avoided (no decompressor in the kernel today).

Estimated total ≈ **1 MB** — small enough that download failures are cheap to retry.

### 6.2 Where the payload comes from (URL scheme)

**v1 (works with the TLS client exactly as it is today):**

```
GET https://api.github.com/repos/LuisErnestoZamb/reemplazo/contents/<path>/payload.tar
Accept: application/vnd.github.raw
Connection: close
```

- `api.github.com` terminates at the **USERTrust ECC** root we already pin
  *(verified §1.3)* — zero TLS changes.
- The `raw` media type streams the file **directly, no redirect**; files 1–100 MB are
  supported with this media type ([contents API docs](https://docs.github.com/rest/repos/contents#get-repository-content),
  [100 MB changelog](https://github.blog/changelog/2022-05-03-increased-file-size-limit-when-retrieving-file-contents-via-rest-api)).
- Cost: the payload file is committed to the repo (≈1 MB per release), and
  unauthenticated rate limit is 60 req/h/IP ([GitHub REST limits](https://docs.github.com/rest/rate-limits/rate-limits)) — one request per install, acceptable.

**v2 (proper releases, needs one TLS change):**

```
https://github.com/LuisErnestoZamb/reemplazo/releases/download/<tag>/payload.tar
  → 302 → https://release-assets.githubusercontent.com/…   (verified redirect shape)
```
but `release-assets.githubusercontent.com` chains to **ISRG Root X1**, which our
single-anchor verifier rejects *(verified §1.3)*. Options, in order of preference:

1. **Add ISRG Root X1 as a second trust anchor.** `embedded-tls`'s `CertVerifier`
   hard-codes a single anchor (`webpki.rs`: `core::slice::from_ref(&anchor)` at the
   pinned rev), and its helpers (`certificate_verify_message`) are `pub(crate)`
   *(verified by reading source)* — so this means either a small fork of the pinned
   rev (add a `Certificate::X509s(&[&[u8]])` variant, pass a slice to
   `verify_for_usage`) or a local `TlsVerifier` implementation using public
   `rustls-webpki` APIs (algorithm constants, `EndEntityCert::verify_for_usage` takes
   `&[TrustAnchor]`, and the RFC 8446 §4.4.3 signed-content construction is ~10 lines).
   Both are bounded; the fork is less duplicated-subtlety, the local verifier avoids
   maintaining a fork. **Spike this before committing to releases-based hosting.**
2. Or: host v1 payloads where the chain already matches (the API route above).

**Local/test server**: plain HTTP on `10.0.2.2` (§8) — no certificate problem there,
and no TLS change needed for smoke tests.

### 6.3 Protocol flow (one download)

```
DHCP (existing) → DNS resolve host (existing) → TCP connect (existing)
→ TLS handshake (existing, pinned anchor) [HTTPS only]
→ GET path HTTP/1.1\r\nHost: …\r\nConnection: close\r\n\r\n
→ parse status line + headers and frame the body with the existing
   `net::http::ResponseParser` (Content-Length / chunked /
   close-delimited already covered by RFC 9112 §6.3):
     - 200: stream decoded body chunks straight to the sink — each
       `feed` returns bytes → write them to RAM/disk, never buffer
       the whole response
     - 301/302/307/308: follow `Location` (new connection, new hostname —
       re-run DNS+TLS with the new SNI; bounded to N hops, else fail loudly)
     - anything else: fail loudly with the status line
→ write body into a sink: RAM buffer first (payload ≈1 MB fits easily in
   256 MB QEMU / 2.9 GB real machine), later directly into the FAT file
→ verify: received == Content-Length; SHA-256 (embassy-crypto, already a dep)
   recomputed on the written file when re-read from disk
→ close_notify + FIN (existing paths)
```

Refactor prerequisite: the smokes are hardcoded one-shots (4 KiB plain-HTTP fixed
buffer, 64 KiB `READ_CAP` on the TLS path). Extract a reusable `http_get(url, sink)`
over `Conn` and over `tls::Socket` (which already streams via `Conn::release`),
driving `ResponseParser::feed` per read; keep the smokes as callers so the existing
14-marker gate is untouched.

### 6.4 Integrity

- **TLS already authenticates the channel and the host** (chain, hostname, EKU,
  signatures — `tls.rs` docs). A second signature fetched *over the same TLS session*
  adds nothing against an active attacker; say so honestly in the code comments.
- We still compute **SHA-256 of the payload** during the write and re-verify after
  re-read from disk: this catches truncation/corruption (RAM, disk, driver bugs) —
  the failure class we actually have.
- Optional later: detached ed25519 signature if we ever mirror payloads over
  plain HTTP. `embedded-tls` has an `ed25519` feature and `crypto.rs` already carries
  `verify_ed25519` (feature-gated) — enabling it is cheap when needed.

### 6.5 Failure modes, retry, resume

| Failure | Behavior |
|---|---|
| DNS no answer / timeout | bounded retries (reuse `ATTEMPTS` budget), then `install: DNS failed` → prompt; nothing written yet |
| TLS handshake refused (wrong root, expired cert) | loud error including `embedded-tls`'s refusal reason (its `warn!` logs already surface *why*); hint: RTC unavailable degrades date checks (`tls.rs` docs) |
| HTTP 4xx/5xx, redirect loop | loud error with status line; never treated as payload |
| Body shorter than `Content-Length`, connection EOF | detected → retry from byte 0 |
| Disk write error / disk too small | abort **before** GRUB is touched (§4 ordering) |
| User abort / Ctrl-C | shell builtin prints progress; re-running is always safe |
| **Resume** | v1: restart the whole download (≈1 MB — cheap). `Range: bytes=N-` resume is a later optimization (server support varies; do not block v1 on it) |

### 6.6 Precedents and what we take from them

- **Debian netinst** ([debian-installer](https://www.debian.org/devel/debian-installer/),
  [netinst images](https://www.debian.org/distrib/netinst)): a small bootable medium
  carries the installer; packages/udebs are fetched over HTTP with the installer's own
  stack; checksums are published next to images. *We take:* “small ISO + fetch the
  rest” split and per-artifact hash publication. *We skip:* package management — our
  payload is one file.
- **Alpine netboot** ([wiki](https://wiki.alpinelinux.org/wiki/Netboot)): tiny
  kernel+initramfs fetched over HTTP/TFTP, then `apk` pulls the system from a repo
  over the same network stack. *We take:* the self-hosting principle (the running
  system's stack does the fetching — exactly AGENTS.md's wording).
- **iPXE** ([ipxe.org](https://ipxe.org/)): boot firmware that chains scripts and
  pulls kernels over HTTP. *We take:* only the mental model — GRUB already boots our
  medium, so we need no PXE/iPXE layer; `grub-mknetdir` (present in `grub-common`)
  is the escape hatch if PXE is ever wanted.

---

## 7. Shell UX + smoke-test strategy

### 7.1 Installer UX (serial shell)

New builtins, grown in the established style (`kernel/src/shell.rs`):

```
disks                       # enumerate block devices: id, model, size, bus
install <id>                # guided: confirm (type the disk id), GPT, FAT32,
                            #   fetch or read payload, write files, install GRUB
netinstall <url>            # explicit URL override for testing
```

Interactive prompts (target, confirmation, source=cdrom|network) are plain serial
lines — the same discipline the shell already has (bounded input, fail-soft).
For smoke tests xtask drives the same prompts by writing to QEMU's stdin.

### 7.2 Serving the payload locally in QEMU

Verified facts:

- With slirp, **the guest reaches the host loopback at `10.0.2.2`**
  (“connecting to a port on the gateway IP address will connect to that port on the
  host” — [QEMU networking wiki](https://wiki.qemu.org/Documentation/Networking);
  libslirp special-cases `vhost_addr` → `127.0.0.1` in `socket.c`).
- `guestfwd=tcp:server:port-cmd:command` **spawns the command for each connection**
  with the TCP stream on stdin/stdout (inetd-style) — [QEMU manpage](https://www.qemu.org/docs/master/system/qemu-manpage.html).

Two paths:

1. **Host-QEMU path** (when `host_qemu()` is true): xtask spawns a tiny HTTP server
   on `127.0.0.1:8080`; guest fetches `http://10.0.2.2:8080/payload.tar`.
2. **Container path** (today's reality): `10.0.2.2` is *the container's* loopback, so
   the server must live in the container. Zero-image-change solution — add to
   `qemu_std_args` for the installer smoke:
   ```
   -netdev user,id=net0,guestfwd=tcp:10.0.2.2:8080-cmd:/iso/serve.sh
   ```
   `xtask` writes `serve.sh` next to `os.iso` (already bind-mounted at `/iso`).
   The script is a ~15-line POSIX-sh HTTP responder: read request lines until the
   blank line, emit `HTTP/1.1 200 OK` + `Content-Length: $(wc -c < /iso/payload.tar)`,
   then `cat /iso/payload.tar`. One connection = one process = one GET — a perfect
   match for our client's `Connection: close` style. (Alternatives if this proves
   flaky: add `python3-minimal` to `tools/Dockerfile` and run
   `python3 -m http.server` alongside QEMU; or a second container on a user-defined
   network that the guest addresses directly.)

TLS **cannot** be smoke-tested locally: our verifier pins the USERTrust ECC root and
we do not possess its private key, so no local server can present an acceptable
chain. The TLS leg is therefore tested against the real `github.com`/`api.github.com`
(existing `TLS_OK`, plus milestone 7).

### 7.3 New smoke surfaces

Keep `cargo xtask smoke` exactly as-is (14 markers) — it is the boot/net/HTTP
regression gate. Add:

- **`cargo xtask smoke-install`** — builds ISO, creates a blank
  `target/disk.img` (e.g. 1 GiB), boots with `-cdrom installer.iso -drive
  file=disk.img,format=raw,if=ide`, writes the install script to QEMU stdin, asserts
  the installer marker sequence, **then reboots `disk.img` without the CD** and
  asserts `BOOT_OK … SHELL_OK` from the installed system.
- Host-side asserts after QEMU exits: GPT parse (xtask implements a ~100-line GPT
  reader — the container has no `sfdisk`), `fsck.fat`/`mtools mdir` listing of p2,
  `sha256sum` of the installed kernel vs. build.

---

## 8. Milestones (smallest testable steps)

Each milestone adds its marker(s) to `smoke-install` unless noted; every step is
QEMU-verifiable on this Mac.

1. **`BLK_OK` — IDE block driver (PIO).** New `kernel/src/ata.rs`: PCI-find the PIIX
   IDE controller, IDENTIFY, read LBA0 of an attached blank disk, print model/size
   and the 0x55AA signature. *Verify:* `xtask` gains
   `-drive file=target/disk.img,format=raw,if=ide` in the installer smoke; marker
   `BLK_OK` in order after `E1000_OK`.
2. **`PT_OK` — GPT writer.** Protective MBR + header + 2 entries + CRC32 + backup
   header, written to the blank image, then re-read and self-validated by the kernel.
   *Verify:* `PT_OK`; after QEMU exits xtask parses the image's GPT independently and
   fails the run on mismatch.
3. **`FS_OK` — FAT32 (fatfs spike + formatter).** First a build spike: `fatfs` with
   `default-features = false` compiles for `x86_64-unknown-none` without `alloc`
   (this is the highest-risk unknown — do it as part of this milestone, aborting the
   FAT plan for ext2-in-QEMU-only if it fails). Then `format_volume` on p2, write
   `kernel.elf`, re-read, SHA-256 compare. *Verify:* `FS_OK` in QEMU +
   host-side `fsck.fat -n` and `mcopy -o … ::/kernel.elf` via the tools image.
4. **`GRUB_OK` — installer writes GRUB + installed disk boots.** `xtask iso` builds
   `core.img` (grub-mkimage in container) and stages `boot.img`/`core.img`/installed
   `grub.cfg`; installer performs the §4 write sequence; `smoke-install` then
   **reboots disk.img with no CD** and expects the full `BOOT_OK … SHELL_OK` chain
   from GRUB → FAT → multiboot2. *This is the "bootable installer" milestone — the
   offline installer is end-to-end done at this point (payload files = running
   kernel's own image via `module2`, milestone 5, or a hardcoded minimal set first).*
5. **`MOD_OK` — payload.tar as multiboot2 module.** the `multiboot2` crate's
   `module_tags()` parses module tags;
   grub.cfg gets the `install` menuentry with `module2 /boot/payload.tar`; kernel
   walks ustar headers, prints file list + SHA-256, `xtask iso` builds `payload.tar`.
   *Verify:* `MOD_OK` in the regular boot smoke (CD path), file list matches
   `tar -tf` on the host.
6. **`DL_OK` — streaming download client.** Wrap the existing pieces
   (`Conn`, `tls::Socket`, `net::http::ResponseParser`) into a reusable
   `http_get(url, sink)`; stream ≥128 KiB from the local `guestfwd` server (§7.2)
   into RAM via successive `feed` calls, with `Content-Length`/chunked framing
   already provided by the parser, length + SHA-256 check. *Verify:* `DL_OK`
   marker in `smoke-install` with `serve.sh` present — no external network needed.
   (Deliberately named `DL_OK`, not `HTTP_OK`: the latter is taken by the boot
   smoke's HTTP milestone.)
7. **`TLSGET_OK` — real HTTPS fetch.** Same client over `tls::Socket`; download
   `payload.tar` from `api.github.com` (contents API, raw media) into RAM; assert
   status 200, `Content-Length`, and length/hash self-consistency. *Verify:* marker in
   `smoke-install` (needs outbound network — same requirement the existing smoke
   already has). If the v1 URL scheme ever changes to Releases, this milestone's
   scope includes the second-root spike (§6.2).
8. **`INST_OK` — scripted offline install end-to-end.** `disks`/`install` builtins,
   drive the full flow from the ISO (`module2` payload) into `disk.img`; marker
   `INST_OK`, then automatic reboot from disk → `BOOT_OK`. *Verify:* `cargo xtask
   smoke-install` green.
9. **`NETINST_OK` — network install end-to-end.** Same flow with
   `netinstall http://10.0.2.2:8080/payload.tar` (payload from `serve.sh`), reboot
   from disk. *Verify:* `smoke-install` green with the guestfwd netdev; then a manual
   variant against the real `api.github.com` URL.
10. **`AHCI_OK` + real hardware.** AHCI driver (`8086:27c5`) — first against
    `-device ahci` in QEMU if the `pc` machine accepts it, then on the MacBook via
    Option/C DVD boot: burn installer ISO, install onto the real 120 GB disk, boot it.
    *Verify:* serial markers over the MacBook's serial/USB-serial or QEMU-parity
    checks; human checklist in the milestone commit message (per AGENTS.md: record
    what was actually verified).

Milestones 1–3 are strictly sequential; 5 and 6 are independent of each other;
7 depends on 6; 8 depends on 4+5; 9 depends on 6+8.

### 8.1 FS1 landed — read-only FAT16 (`FAT_OK`)

The read-only first slice of milestone 3 is in (branch `m-fs`).

- **Marker.** `cargo xtask smoke-install` asserts `["BLK_OK", "FAT_OK"]`: the kernel mounts the
  smoke disk's FAT16 volume and reads `/README.TXT` back byte-for-byte (`kernel/src/fs/`, over the
  new `fat` crate). The main `smoke` runs diskless — `ata::probe` returns `None`, `fs::prove` is
  never reached, nothing is printed, and its marker chain is untouched.
- **`fatfs` probe — failed** (the §9.1 spike, run first as ordered). `fatfs` 0.3.6's `no_std` mode
  is wired through `core_io`, whose `build.rs` maps the *exact rustc commit hash* to a config table
  and panics with `Unknown compiler version, upgrade core_io?` on Rust 1.98.1 — the crate cannot
  build for `x86_64-unknown-none` at all. The reader is therefore **from scratch** under
  dependency-policy exception (a): `fat/` — `#![no_std]`, `#![forbid(unsafe_code)]`, zero
  dependencies, 47 adversarial host tests (truncated/bogus BPB, missing `55 AA`, non-power-of-two
  sectors/cluster, FAT12/FAT32 refusals, FAT cycles, cluster beyond the data region, size lying
  beyond the chain, root-region overrun, LFN checksum/sequence/cluster-field rejection, `..`
  traversal, non-existent path). MIT, maintained crates.io presence, and `hadris-fat` (an active
  `no_std` FAT library that appeared after §5 was written) were noted but **not adopted**: the
  milestone's dependency policy admits no crate besides `fatfs`.
- **Formatter.** A ~100-line FAT16 formatter inside `xtask` itself (fixed 64 MiB geometry: 1
  reserved sector, 2 × 64-sector FATs, 512 root entries, 8 sectors/cluster → 16363 clusters, inside
  the FAT16 window). Chosen over `mkfs.fat` in the tools image because it is byte-reproducible on
  any host and adds no toolchain step; `xtask`'s own host test mounts the image it just wrote
  through the same `fat` crate *before* any VM runs. (`dosfstools` and `mtools` are already in
  `tools/Dockerfile`, so `mkfs.fat` remains the drop-in fallback for a different geometry.)
- **LBA0 magic relocation.** The probe magic moved from offset 0 to **62** — the boot sector's
  bootstrap area — in *both* `kernel/src/ata.rs` (`MAGIC_OFFSET`) and `xtask`
  (`DISK_MAGIC_OFFSET`). Offsets 0..62 are the jump, OEM name and BPB a real FAT boot sector must
  carry, so a magic string there would break the spec (and our own reader refuses it). Probe
  semantics are unchanged: same 17 bytes, same wrapping-sum checksum byte immediately after.
- **Boot order.** A valid `55 AA` at LBA0 makes the disk genuinely bootable, and with QEMU's
  default order SeaBIOS executes the volume's bootstrap so the ISO never boots *(verified in this
  milestone: a `jmp $` at offset 62 hangs the guest)*. The smokes now pin `-boot order=dc`
  (CD-ROM first, disk second).

Still open for milestone 3 proper: the FAT32 write path and the GPT wrapper from milestone 2, both
blocked on the ATA write milestone.

---

## 9. Open questions / risks

1. **`fatfs` without `alloc` on `x86_64-unknown-none`** — highest technical risk;
   spike first (milestone 3). Fallback: enable the kernel's first bump allocator for
   FAT caches, or drop to a minimal FAT16 writer of our own (small, but then `fatfs`
   tooling parity is lost). ***Resolved by the FS1 probe: the spike failed — `core_io`'s
   build script rejects modern rustc — so the fallback (a from-scratch reader) is what
   landed, see §8.1.***
2. **Second TLS root** (only if we move to GitHub Releases) — fork-vs-local-verifier
   decision (§6.2); both bounded, neither urgent for v1.
3. **`guestfwd` vs slirp's `10.0.2.2`-is-host special case** — confirm in milestone 6
   that a `guestfwd` binding on `10.0.2.2:8080` wins over the host-loopback mapping
   (expected: explicit bindings are matched first).
4. **api.github.com unauthenticated rate limit** (60/h/IP) — fine for installs; if CI
   ever hammers it, pin the payload fetch in smoke to the local server and keep the
   real fetch as an opt-in `smoke-real` variant.
5. **Redirect following** — `Location` handling does not exist yet (the parser
   frames bodies but never interprets 3xx). Needed only for the Releases URL shape
   (§6.2); the v1 `api.github.com` route is redirect-free. Decide in milestone 7
   whether to implement bounded redirect-following or fail loudly on 3xx for v1.
6. **AHCI on QEMU `pc` machine** — `-device help` shows `ich9-ahci`; whether it
   attaches cleanly to the `pc` machine (vs. `q35`) is untested; worst case AHCI is
   validated only on real hardware (milestone 10), which AGENTS.md already accepts for
   sky2.

---

## 10. Sources

Local (verified in this checkout): `xtask/src/main.rs` (`iso()`, `smoke()`,
`qemu_std_args()`), `tools/Dockerfile`, `iso/boot/grub/grub.cfg`,
`kernel/src/{main,tcp,tls,shell}.rs`, `net/src/http.rs` (`ResponseParser`),
`mbi/src/lib.rs` + `mbi/tests/hostile.rs`, `kernel/Cargo.toml`
(pinned `embedded-tls` rev `63c59a1`), container inspection via `dpkg -L`, `grub-mkimage`
size measurements, `qemu-system-x86_64 -device help`, `openssl s_client` chain checks
(2026-11-21).

- GRUB manual — BIOS installation (MBR gap, GPT bios_grub): https://www.gnu.org/software/grub/manual/grub/html_node/BIOS-installation.html
- GRUB sources — `grub-bios-setup.c`: https://git.savannah.gnu.org/cgit/grub.git/tree/util/grub-bios-setup.c ; `boot.S`: https://git.savannah.gnu.org/cgit/grub.git/tree/grub-core/boot/i386-pc/boot.S
- `fatfs` crate + no_std usage: https://crates.io/crates/fatfs · https://github.com/rafalh/rust-fatfs · https://docs.rs/fatfs/latest/fatfs/
- `ext2` crate (std-only): https://docs.rs/ext2/latest/ext2/ · `efs` (no_std ext2, GPL-3.0): https://crates.io/crates/efs · https://codeberg.org/RatCornu/efs
- ext2 background: https://wiki.osdev.org/Ext2 ; FAT background: https://wiki.osdev.org/FAT
- GPT/MBR specs: https://wiki.osdev.org/GPT · https://wiki.osdev.org/MBR
- AHCI: https://wiki.osdev.org/AHCI ; MacBook2,1 SATA probe (8086:27c5 AHCI): https://linux-hardware.org/?log=hwinfo&probe=61f09eb46a
- QEMU user networking, `10.0.2.2` → host: https://wiki.qemu.org/Documentation/Networking ; `guestfwd` syntax: https://www.qemu.org/docs/master/system/qemu-manpage.html ; net devices overview: https://qemu.org/docs/master/system/devices/net.html
- GitHub contents API (raw media, 100 MB): https://docs.github.com/rest/repos/contents#get-repository-content · https://github.blog/changelog/2022-05-03-increased-file-size-limit-when-retrieving-file-contents-via-rest-api ; rate limits: https://docs.github.com/rest/rate-limits/rate-limits
- HTTP/1.1 (chunked, redirects): https://www.rfc-editor.org/rfc/rfc9112 ; https://www.rfc-editor.org/rfc/rfc9110
- ustar tar format: https://www.gnu.org/software/tar/manual/html_node/ustar.html
- Debian netinst / d-i: https://www.debian.org/devel/debian-installer/ · https://www.debian.org/distrib/netinst
- Alpine netboot: https://wiki.alpinelinux.org/wiki/Netboot
- iPXE: https://ipxe.org/
- TLS 1.3 CertificateVerify content: https://www.rfc-editor.org/rfc/rfc8446#section-4.4.3
