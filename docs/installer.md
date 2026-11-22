# Installer design — bootable ISO + network installer

Status: design (research complete) + **FS1 landed** — FAT16 reader and its `FAT_OK`
smoke marker (§8.1) + **FS2 landed** — FAT16 write path and its `FS_WRITE_OK` marker
(§8.2) + **I1 landed** — GPT + install-to-disk and its `INST_OK` marker (§8.3) +
**I2 landed** — the network installer and its `NETINST_OK` marker (§8.4) +
**FS3 landed** — directories/LFN writes and `FS_TREE_OK` + the full-tree git checkout (§8.5) +
**I1b landed** — GRUB boot code on the installed target and the standalone
disk-boot proof (§8.6).
Scope: the two installer deliverables from
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

**As landed (I1b, §8.6) — the exact mechanism differs from the sketch above,
deliberately and documented there:** the kernel never writes a
`/boot/grub/grub.cfg` on p2. Instead `grub-mkimage -c` embeds a three-line early
config *inside* `core.img` (`search --no-floppy --file /KERNEL.ELF --set=root`,
`multiboot2 /KERNEL.ELF`, `boot`), so the installed disk needs exactly one file on
p2 — the kernel — and no `/boot/grub` directory. `grub-install` is still absent
from the image, but `grub-bios-setup` **is** present (at
`/usr/lib/grub/i386-pc/grub-bios-setup`); it could not be used directly for the
build proof (it failed with `failed to get canonical path of
'/run/host_mark/private'` on Docker Desktop for macOS — it probes host devices),
so the installer replicates its write patch set from its source (`util/setup.c`,
`grub-core/boot/i386/pc/{boot,diskboot}.S`, `include/grub/i386/pc/boot.h`) and the
host verifier compares the result byte-for-byte with the ISO artifacts
*(verified: the hand-patched image boots in QEMU)*.

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

### 8.2 FS2 landed — FAT16 write support (`FS_WRITE_OK`)

The write slice is in (branch `m-fs2`); it unblocks editor save, git checkout and the installer's
file operations on FAT16.

- **Marker.** `cargo xtask smoke-install` now asserts `["BLK_OK", "FAT_OK", "FS_WRITE_OK"]`: after
  `FAT_OK`, the kernel writes `/RESULT.TXT` (`kernel/src/fs::write_proof`), then **re-mounts from
  scratch** — a fresh `fat::Fat16` over a fresh block handle, no state from the write surviving —
  reads the file back byte-exact, and re-reads `/README.TXT` to prove the write didn't clobber its
  neighbour. Any failure with a drive present is `FATAL: fs: …` + halt; no drive stays silent (the
  main smoke's 22 markers are untouched).
- **ATA writes.** `kernel/src/ata.rs` gains PIO `WRITE SECTORS` (LBA28): same discipline as the
  reads — drive-select + 400 ns settle, bounded polls (`POLL_LIMIT`, a new bounded DRQ-clear wait),
  1..=256 sectors per request, refusal past the IDENTIFY-reported capacity, `SAFETY` comments on
  every port I/O, no DMA/IRQ (future work, as documented for reads). The probe/magic-at-offset-62
  semantics are unchanged.
- **Writer.** `fat/src/write.rs` (the `fat` crate stays `no_std`, `forbid(unsafe_code)`, zero
  deps): `write_file` (create-or-overwrite) and `create_file` (no-clobber) — in-place overwrite,
  chain grow (first-fit free-FAT allocation, both mirrors updated), truncate with tail freeing
  (cycle-bounded, no double-free), creation in the root **and in existing subdirectories** (no
  `mkdir`). Refusals: disk/directory full (`NoSpace`, pre-checked before any mutation), corrupt
  chain mid-write (FS1's validators: cycle/out-of-range/free-entry → `BadChain`, checked *before*
  mutating so a refused write leaves the disk byte-identical), non-8.3 names (`InvalidName`),
  out-of-range timestamps (`Stamp`), read-only device (`ReadOnly`), `NotAFile`/`NotFound`/`Exists`.
- **8.3 naming decision:** names must be 8.3-encodable (1..=8 base, 0..=3 ext, FAT's legal
  character set); lowercase is folded to uppercase on disk; long/exotic names are **refused**, never
  mangled — this crate writes no LFN entries. Overwriting an existing file *through* its long name
  still works (the stored 8.3 name is kept).
- **Flush policy:** write-through, no `flush()` — every FAT/data/directory sector is written inside
  the operation, ordered **FAT → data → directory entry** (the entry readers consult is the commit
  point, written last). **Crash consistency is explicitly NOT a goal yet**: no journal, no flush
  barriers, no drive `FLUSH CACHE` (0xE7) — power-loss ordering is a later milestone.
- **Mount hardening:** `fat::Fat16::mount` now refuses a FAT too small to hold every cluster entry
  (spill would cross into the next FAT/root), with a hostile test.
- **Host tests:** `fat/tests/write.rs` — 23 tests (round-trips, grow/shrink across cluster
  boundaries, full-disk and slot-exhaustion refusals, cycle/out-of-range refusals leaving the image
  byte-identical, no-double-free, stale-LFN clearing, LFN overwrite, mirror sync, invalid
  names/stamps, read-only device, subdirectory create, plus a 120-op **xorshift-seeded oracle**
  against a `Vec` model re-mounted after every op); `fat/tests/hostile.rs` stays green (47 FS1
  tests + 1 new mount-hardening test = 48). Total: **71 host tests** in `fat/`.
- **Still open (FS3+):** crash consistency (journal/flush ordering, drive `FLUSH CACHE`),
  unlink as a public operation, cross-file cross-link detection (needs a visited set
  — i.e. the heap), FAT32, and the GPT wrapper (milestone 2).
- **Still open (FS3+):** crash consistency (journal/flush ordering, drive `FLUSH CACHE`), LFN
  writes, `mkdir`/unlink as public operations, cross-file cross-link detection (needs a visited set
  — i.e. the heap), FAT32, and … the GPT wrapper — which is exactly what **I1** landed next.

### 8.3 I1 landed — GPT + install-to-disk (`INST_OK`)

The install-to-disk milestone is in (branch `m-installer-full`). `cargo xtask smoke-install`
now asserts `["BLK_OK", "FAT_OK", "FS_WRITE_OK", "INST_OK"]` and, after QEMU exits, re-verifies
the target image on the host.

- **Invocation choice (the doc was silent for boot time):** the install proof runs **at boot,
  immediately after `fs::prove`** (`kernel/src/main.rs` → `install::prove`), with the same
  neutrality discipline: no source disk → never reached; no *marked* target disk → silent
  `return`, zero output. The interactive `disks`/`install <id>` builtins of §7.1 remain the
  future path for unmarked real hardware (they need typed confirmation — a boot-time wipe of an
  unmarked disk would violate the fail-closed rule, so the boot path only ever touches a disk
  carrying the `reemplazo-target-v1` marker xtask writes).
- **Second disk.** `smoke-install` creates **two** images after `iso()`: `disk.img` (the FS1/FS2
  FAT16 source, unchanged contract) and `target.img` — 64 MiB of zeros carrying only the wipe
  marker at LBA0 offset 62 (no BPB, no `55 AA`: never bootable, provably *not* the source).
  Both attach as `-drive …,if=ide`: source = master, target = slave; `ata::probe_target(unit)`
  skips the source unit and requires the target marker.
- **GPT: `gptwire` crate** (new workspace member, `#![no_std]`, `#![forbid(unsafe_code)]`,
  zero deps). Reads **and** writes the full layout of §3.2: protective MBR (type `0xEE`,
  start LBA 1, `0xFFFFFF` end CHS per UEFI spec Table 17), header at LBA1 with CRC-32 over the
  header with its own CRC field zeroed, 128 × 128 B entry array (hard cap — a `u32::MAX` count
  from a corrupt disk is refused before any storage is committed), mirrored backup whose
  **bytes** are re-checksummed, pairwise overlap + usable-range validation, and checked
  LBA→byte arithmetic at every read (`lba_bytes` is the choke point). Dependency-policy
  exception (a), cited from §2(3): *"the OS partitions itself … it is the only option"*; the
  CRC32 is the §3.2 budgeted glue. **49 adversarial host tests** (`gptwire/tests/hostile.rs`):
  known CRC vectors, write→read round-trips, and one-field corruptions each asserting the exact
  refusal (signature, revision, header size/CRC/reserved, current/backup LBA, usable range,
  absurd/over-cap entry counts, entry size, array bounds/CRC, backup signature/CRC/offset/mirror
  drift, corrupt backup bytes, MBR garbage vs. missing `0xEE`, out-of-range/inverted/overlapping
  partitions, truncation, read-only writes, name/GUID handling).
- **Formatter extraction (the choice the milestone asked for):** the FS1 xtask formatter moved
  into the `fat` crate as **`fat::format_fat16`** — one implementation shared by xtask's
  `write_disk_image` and the kernel's installer (the doc's "reuse/extract" option). Unlike the
  FS1 fixed constants, the geometry is *derived* from the device size (smallest sectors/cluster
  that lands in the FAT16 window, FAT sized from an upper bound on the cluster count, `hidden`
  sectors carrying the partition offset), it refuses what no cluster size can express
  (`TooSmall`/`NotFat16`), and it **re-mounts its own output through `Fat16::mount` before
  returning**. Host tests: `fat/tests/format.rs` (8) — geometry pinned for the real sizes
  (64 MiB superfloppy, the 126943-sector p2, 8 MiB, ~2 GiB, refusal edges), boot-sector
  contract, file round-trip, hidden-sectors, label/refusal cases. `fat` totals **79 host tests**.
- **Install flow (`kernel/src/install.rs`):** validate target capacity (≥ 8 MiB) → write the
  §3.2 layout (p1 `bios_grub` 1 MiB @ 1 MiB, p2 Microsoft Basic Data to the last usable LBA —
  GUIDs from `gptwire`, verified against Microsoft's `PARTITION_BASIC_DATA_GUID`) → **re-read
  through `gptwire::read`** (the marker asserts the device's state, not our intent) → format p2
  with `fat::format_fat16` → copy `/README.TXT` + `/RESULT.TXT` from the source volume (bounded
  4 KiB buffers, `BufferTooSmall` refuses a lying size) → **re-mount p2 from scratch** and read
  both back byte-exact → `INST_OK`. Every failure with a target present is
  `FATAL: install: …` + `halt()`.
- **ATA driver change this milestone forced:** `read_sectors`/`write_sectors` now issue **one
  single-sector command per 512 B** instead of one command for the whole request. FS2 had only
  ever proven single-sector writes; the GPT's first 32-sector write failed exactly at the
  multi-sector DRQ handshake (QEMU re-asserts DRQ for the next sector immediately, so a
  "wait DRQ low" completion poll never observes the low window — `FATAL: install: Write` in the
  first I1 run). One command per transfer means only the proven handshake is ever assumed; cost
  is ~10 port accesses per sector, noise next to the 256-word data phase.
- **Host-side verify (§7.3's "assert after QEMU exits"):** `xtask::verify_installed_image`
  re-reads `target.img`, parses the GPT with `gptwire`, checks p1/p2 bounds against the layout
  constants, mounts p2 through `fat` and requires both payload files byte-exact against the
  kernel-side constants (`README_CONTENT`/`RESULT_PAYLOAD`, duplicated as everywhere because
  host crates cannot depend on the kernel).
- **GRUB-on-target: deferred to I1b, honestly split — now resolved (§8.6).** §4's plan
  needed `boot.img`/`core.img` *bytes inside the kernel*, and at I1 time the kernel had
  neither an ISO9660 reader nor the multiboot2-module payload path (milestone `MOD_OK`) —
  the artifacts existed only on the ISO. Embedding them at kernel-build time would also
  invert the build order (`core.img` is made by `grub-mkimage` *during* `xtask iso`, after
  the kernel compiles). So I1 landed without GRUB and `INST_OK` asserted only what it
  actually did. I1b (§8.6) delivered the bytes as a multiboot2 **module** and the write
  sequence, so the installed disk is now bootable; the §4 ordering rule (GRUB boot code
  last = commit point) is honored by the GRUB step being the final action of
  `install_payload`.
- **Not in I1:** `PT_OK`/`FS_OK` are folded into `INST_OK` (the GPT write + re-read and the FAT
  format + read-back are asserted inside it — the milestone table's separate markers would be
  redundant in the chain); shell builtins (§7.1), reboot-from-disk assert (needs GRUB), AHCI.
- **Verified:** `cargo xtask check` exit 0; `cargo xtask smoke` PASS, all 24 markers unchanged
  (diskless neutrality: `install::prove` never reached, and silent without a marked target);
  `cargo xtask smoke-install` PASS — `BLK_OK + FAT_OK + FS_WRITE_OK + INST_OK` plus the host
  verify line; `gptwire` 49 + `fat` 79 + `xtask` 2 host tests green.

### 8.4 I2 landed — network installer (`NETINST_OK`)

The network half of the deliverable is in (same branch). `cargo xtask smoke-install` now
asserts `["BLK_OK", "FAT_OK", "FS_WRITE_OK", "INST_OK", "NETINST_OK"]` and the host verifier
compares the installed kernel against the built binary.

- **Invocation:** still boot-time (the doc's §7.1 `netinstall <url>` builtin stays open as
  later work): `install::netprove` runs **after the boot network chain** — it needs the NIC,
  which is not up when `INST_OK` runs — gated on the source disk *and* the target found in
  `kernel_main`. The target is probed **exactly once, before `INST_OK`**: the first install's
  protective MBR overwrites LBA0, i.e. the very place the `reemplazo-target-v1` marker lives,
  so a re-probe after the offline install could never succeed (the first I2 run failed
  silently on exactly this — recorded here because the symptom was a *missing* marker, not an
  error line).
- **Serving the payload (§7.2's container path, chat-mock pattern):** xtask builds
  `payload.tar` at boot with the host's `tar --format ustar` — `README.TXT` + **the actual
  built kernel** (`target/x86_64-unknown-none/release/kernel`, the system payload of §6.1;
  GRUB's `boot.img`/`core.img` join it with I1b's `MOD_OK` payload path) — wraps it in a
  canned `HTTP/1.1 200` with a computed `Content-Length` (`payload-http.txt`), and the
  container's `MOCK_LOOP` gains a second bounded `nc` responder on `127.0.0.1:8080`
  (guest→`10.0.2.2:8080` lands on the container's loopback, exactly like `:8099`; no
  `guestfwd` needed — §9.3's question never had to be answered). The host-QEMU backend's
  `chat-mock` subcommand serves both ports. No internet needed.
- **The client:** plain-HTTP `GET /payload.tar` on `tcp5` (local port 49163 — the `ai`
  exchange's socket, left TimeWait/Closed by the A5 proof, which is what smoltcp `connect`
  accepts; `ai.rs` documents the observation), `net::http::ResponseParser` framed
  incrementally into a **bounded 2 MiB `static`** (`DOWNLOAD`; status 200 + `Content-Length`
  == received asserted fail-closed, oversize refused), clean FIN → TimeWait close. No DNS
  (the host is the dotted quad from `net::SLIRP_GATEWAY`), no TLS (impossible locally per
  §7.2 — the real `api.github.com` fetch stays milestone 7/9's later work).
- **ustar walker** (`install::parse_tar`, in-kernel): every header checksum-validated
  (unsigned *and* the historical signed sum accepted — both equal on real `bsdtar`
  output, which is what the parser's rules were pinned against: magic `ustar\0`, type `0`,
  octal size with checked arithmetic, data range inside the buffer, 1..=100-byte printable
  ASCII name with no `/` and an empty `prefix`, ≤8 files, zero block or clean end
  terminates). pax/GNU extension entries are **refused**, not skipped past blindly.
- **Install:** the *same* `install_payload` as `INST_OK` — GPT rewrite + validate, format,
  copy, fresh re-mount, byte-exact read-back — so both markers assert identical disk work.
  The format's cluster floor is now 16 sectors/8 KiB
  (`fat::FormatOpts::min_sectors_per_cluster`, new knob): the writer's first-fit allocation
  probes the FAT once per cluster, and at 1 KiB clusters a 1.7 MB kernel meant ~1700
  O(n²)-shaped scans of sector reads — measured too slow for the smoke budget, ~210 at
  8 KiB (the knob exists because of this measurement; `fat/tests/format.rs` pins it).
- **Host verify (§7.3):** after QEMU exits, xtask re-parses the target's GPT, mounts p2 and
  compares `/KERNEL.ELF` **byte-for-byte against the built kernel binary** — ground truth
  that catches a corrupted download even though the guest already verified its own copy —
  plus `/README.TXT` against the payload constant.
- **Not in I2 (later milestones):** the §7.1 `netinstall <url>` shell builtin, the real
  `api.github.com` HTTPS fetch (milestone 7/`TLSGET_OK`, needs no local server), redirect
  following (the local server is a single 200), `Range` resume (§6.5: restart instead),
  payload signatures (§6.4's honest "TLS authenticates; we hash for corruption" stance
  applies once the fetch is TLS).
- **Verified:** `cargo xtask check` exit 0; `cargo xtask smoke` PASS with all 24 markers
  unchanged and **zero** installer lines (diskless neutrality); `cargo xtask smoke-install`
  PASS — `BLK_OK + FAT_OK + FS_WRITE_OK + INST_OK + NETINST_OK` with
  `netinstall: 1717248 bytes received` / `payload carries 2 files`, plus the host line
  `host verify ok — GPT + FAT16 p2 + installed kernel byte-exact`; `gptwire` 49 +
  `fat` 81 + `xtask` 2 host tests green.

### 8.5 FS3 landed — directories + LFN writes (`FS_TREE_OK`, full checkout)

`fat` now creates directories and writes long names; the G3/G4 checkout is the **whole**
depth-1 tree instead of root-only 8.3 blobs. Branch `m-fs3`.

- **`mkdir`.** `Fat16::create_dir` / `create_dir_all` (branch `fat/src/tree.rs`): allocate a
  cluster, zero it (it may have held file data), write `.` (own cluster) and `..` (the parent's
  first cluster, `0` when the parent is the fixed root), then the parent's entry **last** — the
  same FAT → data → directory commit order FS2 documents. The fixed root never gets `.`/`..`.
  Refusals before any mutation: no free cluster (`NoSpace`), no contiguous run of
  `1 + LFN entries` slots (`NoSpace`), name collision (`Exists`), invalid path (`Path`).
- **Path API.** `create_dir(path)`, `create_dir_all(path)` (`mkdir -p`, bounded to 32
  components / 1024 bytes), `write_file_all(path, bytes)` (creates missing parents, then writes)
  and the existing `read_file`. Every component is validated **before the first write**: absolute,
  no empty/`.`/`..` component (so no traversal or escape), bounded component count and length.
  `Fat16::kind(path)` reports `File`/`Dir` for the read side.
- **LFN writes.** A name that is not 8.3-encodable gets a unique uppercase 8.3 alias
  (`NAME~N.EXT`, illegal characters dropped, base shrunk for ≥2-digit suffixes, numeric tail
  probed `1..=9999`, then `NameConflict`) plus the spec's LFN chain: UTF-16LE, 13 units per
  entry, sequence numbers descending with `0x40` on the physically first entry, the classic
  rotate-right checksum over the alias, `0x0000` terminator then `0xFFFF` padding, LFN entries
  written **before** the 8.3 entry. Names > 255 UTF-16 units (a surrogate pair counts twice) and
  FAT-illegal characters (`/\:*?"<>|`, control bytes) are `InvalidName`. Reusing a deleted slot
  clears stale LFN parts first, exactly like FS2's create path.
- **Allocation hint.** The allocator keeps a monotonic search hint (`Cell<u32>`, re-verified
  against the FAT on every hit, wraps to `2..hint` when the tail is full) so a 2 MiB checkout is
  a linear scan instead of O(n²) — the difference between ~35 s and ~2 s in QEMU. It is never a
  cache: every candidate is read back as `0x0000` before it is handed out.
- **Marker + checkout.** `cargo xtask smoke-install` asserts
  `["BLK_OK", "FAT_OK", "FS_WRITE_OK", "FS_TREE_OK", "GIT_CHECKOUT_OK"]`: after `FS_WRITE_OK`,
  the kernel creates `/sub/dir/deep/nested-long-name-file.txt` and `/SUB/DIR/PLAIN.TXT`,
  re-mounts from scratch and reads both back byte-exact plus the FS2 payloads (`FS_TREE_OK`);
  then the network phase checks the fetched repo's **whole** tree out (directories created, long
  names via LFN writes, symlinks/gitlinks counted as skipped), asserts
  `git: checkout: N of N file(s) written in D dirs, 0 skipped`, re-mounts and reads `/README.md`
  and the nested `docs/hardware.md` back byte-exact with a content fragment each. Observed this
  milestone: **112 files in 53 dirs, 0 skipped**.
- **Host tests:** `fat/tests/tree.rs` — 31 new tests (mkdir round-trips and re-mounts, `.`/`..`
  clusters and the root special case, nested + deep parent chains, `create_dir_all` idempotence,
  exact LFN entry bytes against an independent spec oracle, 13/14/26/27-unit and 255-unit
  boundaries, alias collisions and `~10` probing, alias-vs-short-name avoidance, Unicode and
  non-BMP names, path-escape refusals, full-disk/no-slot refusals leaving the image
  byte-identical, stale-LFN clearing, handcrafted chains and checksum corruption, plus a 40-op
  randomized tree oracle). Total `fat/` suite: **102 host tests** (the 71 FS1/FS2 ones stay
  green; the one FS2 test that asserted long names are refused now asserts the unrepresentable
  names that remain refused).
- **Still open (FS3+):** directories are never grown past their existing extent (a full
  directory is `NoSpace`; no cluster extension yet), no `unlink`, crash consistency
  (journal/flush ordering, drive `FLUSH CACHE`), cross-file cross-link detection (needs the
  heap), FAT32, and the GPT wrapper (milestone 2).

### 8.6 I1b landed — GRUB on the target, the installed disk **boots** (disk-boot phase)

Branch `m-grub`. `cargo xtask smoke-install` now ends with a **second QEMU** that boots
`target.img` alone (no ISO) and asserts the installed system's chain. This is the milestone
that makes "install" mean "bootable".

- **Artifacts (`xtask iso`, in the tools image).** `grub-mkimage -O i386-pc` builds
  `core.img` (measured **151 317 B**) with exactly the boot-critical modules and an embedded
  early config; `boot.img` (**512 B**, pristine, from `/usr/lib/grub/i386-pc/boot.img`)
  is concatenated after it:
  ```
  grub-mkimage -O i386-pc -o core.img \
      -p '(hd0,gpt2)/boot/grub' -c early.cfg \
      biosdisk part_gpt fat multiboot2 normal search search_fs_file
  cat boot.img core.img > grubpayload.bin        # 151 829 B
  ```
  `early.cfg` is generated by xtask and is what the installed disk executes
  (`grub_main` runs the embedded config after `grub_load_modules`, so every command it uses
  is already registered — GRUB 2.12 `grub-core/kern/main.c`):
  ```
  search --no-floppy --file /KERNEL.ELF --set=root
  multiboot2 /KERNEL.ELF
  boot
  ```
  `search` makes the disk independent of the BIOS drive number; the `-p` prefix sets
  `(hd0,gpt2)` as the fallback root, so a failed search still boots a single-disk machine.
  **No `/boot/grub/grub.cfg` is written to p2** — the installed disk carries only
  `/KERNEL.ELF` (plus README/RESULT). A menu, a p2 config and `timeout` UI are later work.
- **Delivery: two multiboot2 modules.** The ISO's GRUB config gained
  `module2 /boot/grubpayload.bin grubpayload` and `module2 /boot/kernel.elf payload`; the
  kernel's `install::capture_modules` copies each recognized module into a kernel-owned
  static **before `memory::init`**. Why: GRUB's module memory is not reserved in the
  multiboot2 memory map (only the kernel image and the MBI are), so the frame allocator
  would eventually hand those frames to the heap and overwrite the artifacts. `mbi` grew
  `check_module(start, end, cap)` — non-zero start, `end > start`, length ≤ a *consumer*
  cap (1 MiB p1 for GRUB; the 4 MiB download bound for the kernel) — with six adversarial
  host tests (null start, empty, reversed, cap edge, whole-4-GiB range). The capsule is
  `grubpayload.bin = boot.img (first 512 B) ‖ core.img`; the kernel splits at that fixed
  boundary and validates the artifacts (boot `0xEB`/`55 AA`, core ≥ 2 sectors,
  block-list terminator at 488..500, default segment `0x820` at 510).
- **The write sequence (`install::install_grub`) = `grub-setup`'s, from its source.**
  `grub-bios-setup` is present in the image but unusable here (it failed with
  `failed to get canonical path of '/run/host_mark/private'` on Docker Desktop macOS — it
  probes host block devices), so the kernel implements the documented patch set:
  1. **`core.img` → p1 (LBA 2048)**, all sectors (padded to 512). The first sector is GRUB's
     `diskboot`; its block list at **500..512** (`{ u64 start; u16 len; u16 segment }`,
     growing downward, zero terminator at 488..500) is *recomputed*: contiguous embedding ⇒
     one entry `start = 2048+1`, `len = ceil(core/512)-1`, `segment = 0x820` — exactly
     `util/setup.c`'s `save_blocklists` result for contiguous sectors and its
     `GRUB_BOOT_I386_PC_KERNEL_SEG + 0x20` initial segment.
  2. **`boot.img` → LBA0** (`util/setup.c`): copy the existing sector's BPB
     (`0x03..0x5a`) and NT-magic + disk-signature + partition table (`0x1b8..0x1fe`, which
     holds the GPT protective MBR entry) into the artifact; patch
     `GRUB_BOOT_MACHINE_KERNEL_SECTOR` at **0x5c** with an *unaligned 64-bit LE* p1 LBA
     (`write_rootdev`), set `boot_drive = 0xFF` at 0x64, and replace the drive-check `jmp`
     at **0x66** with `nop; nop` (the hard-disk workaround). The `0xEE` record and `55 AA`
     signature survive; `gptwire::read` still parses the disk.
  3. **Read both back** byte-exact (LBA0 whole sector, p1's first sector) and re-check the
     protective MBR — the marker asserts the device.
- **Ordering = commit point.** `install_payload` already does GPT → format → files →
  fresh-mount read-back; GRUB is the final step, after every p2 byte proved. Both the
  offline and the network install end with the same `install_grub`, so `INST_OK` and
  `NETINST_OK` now prove identical, bootable disk work. The offline path also writes
  `/KERNEL.ELF` from the `payload` module, so an install with **no network** boots too.
- **Disk-boot proof.** After the install VM exits and `verify_installed_image` re-checks
  GPT + p2 + `/KERNEL.ELF` + **the GRUB bytes against the ISO artifacts**
  (`grubpayload.bin` is still in `target/iso-root/boot`; the host rebuilds the same LBA0
  patch from the image's own preserved fields and the same block list, then compares
  LBA0 and p1 byte-for-byte), xtask starts a second container/QEMU with
  `-drive file=/iso/target.img,if=ide,format=raw -boot order=c` and **no ISO**, same
  e1000/USB devices and the chat mock. Asserted markers:
  `BOOT_OK → VGA_OK → MEM_OK → ALLOC_OK → RTC_OK → PCI_OK → E1000_OK → SHELL_OK`
  within **45 s**. `SHELL_OK` is the last line of the whole fail-closed boot chain, so it
  implies the network/AI/browser phases passed too; the asserted prefix names the
  disk-relevant ones (MBI handoff, VGA mirror, allocators, PCI, NIC). The disk markers
  (`BLK_OK`/`FAT_OK`/`INST_OK`/…) are correctly **absent** — LBA0 is now `boot.img`, so
  `ata::probe` finds no installer source magic and the installer stays silent; that is the
  neutrality rule observed from the booted system's side. The milestone table's proposed
  `GRUB_OK` marker is deliberately **not** added (the boot chain's 30 markers stay
  untouched): a marker printed by the *installer* would prove intent, while the
  standalone disk boot is the observable fact.
- **Not in I1b:** a p2 `/boot/grub/grub.cfg` + menu (`search`-based, timeout UI), GRUB's
  graphical/video modules (text only), an INI/`grubenv` (no writable config yet), AHCI
  (the disk-boot proof is QEMU's IDE; the MacBook's ICH7 needs the separate AHCI driver),
  crash consistency around the GRUB write, and `grub-bios-setup` parity for block-listed
  (fragmented) installs — this implementation requires the contiguous p1 it creates, which
  the §3.2 layout guarantees.
- **Verified:** `cargo xtask check` exit 0; `cargo xtask smoke` PASS, all 30 markers
  unchanged (the ISO boot now prints one extra `mbi: module payloads captured: grub … B,
  kernel … B` line between `VGA_OK` and `MEM_OK`; marker order untouched); `cargo xtask
  smoke-install` PASS with the install chain + host verify + the standalone disk boot
  (recorded in the commit message); `cargo xtask smoke-ssh` PASS (ISO boot path unchanged);
  `mbi` unit tests now 9 (4 range + 5 module) plus its 10 adversarial `tests/hostile.rs`
  cases.

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
