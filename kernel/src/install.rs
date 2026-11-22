//! Milestones **I1** (docs/installer.md §3.2, §4, §8.3), **I2**
//! (§6, §8.4) and **I1b** (§4, §8.6): the install-to-disk flow
//! (`INST_OK`), the network installer (`NETINST_OK`) and the GRUB boot
//! code that makes the installed target **bootable on its own**.
//!
//! Given the *source* disk (the FS1/FS2 volume — already proven by
//! `crate::fs::prove`) and a *target* disk found by
//! [`ata::probe_target`], the offline flow is exactly
//! docs/installer.md's layout and ordering:
//!
//! 1. **GPT** — protective MBR + primary/backup headers with CRC32
//!    (the `gptwire` crate, adversarially host-tested), p1 =
//!    `bios_grub` 1 MiB @ 1 MiB, p2 = Microsoft Basic Data taking the
//!    rest of the disk (§3.2's table), then **re-read and validated
//!    through the same parser** — so `INST_OK` asserts what landed on
//!    the device, not what we meant to write.
//! 2. **Format p2 FAT16** — `fat::format_fat16`, the formatter shared
//!    with xtask's disk images (one implementation, one contract,
//!    host-tested in `fat/tests/format.rs`).
//! 3. **Copy the payload** — `/README.TXT` + `/RESULT.TXT` read from
//!    the source volume (the FS1 machinery) and `/KERNEL.ELF` from the
//!    ISO's `payload` multiboot2 module (I1b: the running kernel's own
//!    ELF bytes, so the installed disk boots standalone even offline).
//! 4. **Verify** — re-mount p2 from scratch (fresh `Part` + fresh
//!    `fat::Fat16`, no state from the write surviving) and read every
//!    file back byte-exact.
//! 5. **GRUB (I1b)** — the `grubpayload` module carries GRUB's own
//!    `boot.img` (512 B) + `core.img` (built by `grub-mkimage` during
//!    `xtask iso`); [`install_grub`] writes `core.img` to p1 with the
//!    block list patched to p1's first LBA, then `boot.img` to LBA0
//!    with the partition table preserved and the same LBA patched in
//!    (exactly `grub-bios-setup`'s write sequence, §4/§8.6), and reads
//!    both back. GRUB boot code is the **commit point** and goes last.
//!
//! ## I2: the network installer (`NETINST_OK`)
//!
//! [`netprove`] runs **after the boot network chain** (it needs the
//! NIC), with the same target rules: no marked target → silent
//! `return`. It fetches `payload.tar` (ustar, docs §6.1) from
//! `10.0.2.2:8080` — xtask's in-container `nc` responder, the chat
//! mock's pattern — **over our own stack** (smoltcp + `net::http`'s
//! incremental `ResponseParser`, streamed into a bounded 2 MiB
//! [`DOWNLOAD`] static), walks the tar headers (bounded, checksum-
//! validated), then runs the *same* [`install_payload`] the offline
//! path uses (GPT + FAT + files + GRUB) and reads every file back
//! byte-exact → `NETINST_OK`. The host then re-verifies `target.img`
//! against the **built kernel binary** and the ISO's GRUB artifacts
//! (xtask's `verify_installed_image`).
//!
//! ## Module payloads: copied before the heap exists
//!
//! Both artifacts arrive as multiboot2 **modules** on the installer
//! ISO (`module2 /boot/grubpayload.bin grubpayload`,
//! `module2 /boot/kernel.elf payload`). GRUB's module memory is *not*
//! reserved in the multiboot2 memory map (only the kernel image and
//! the MBI are), so the frame allocator would eventually hand those
//! frames out and overwrite the bytes. [`capture_modules`] therefore
//! copies each recognized module into a kernel-owned static **before
//! `memory::init`** (still interrupts-off, single core) and the
//! installer reads only those copies afterwards.
//!
//! ## Neutrality (diskless boots stay silent)
//!
//! Both proofs are only reached when `ata::probe` found the source
//! disk (the main smoke has no disk at all), and their first action
//! is [`ata::probe_target`]: no second disk, or a second disk without
//! the `reemplazo-target-v1` marker → **`return`, zero output** —
//! `cargo xtask smoke`'s marker chain is untouched, and an unmarked
//! real disk is never wiped (fail-closed; the guided `install <id>`
//! shell builtin of docs/installer.md §7.1 is the future path for
//! unmarked hardware). With a target present, every failure is a
//! loud `FATAL: install: …` + `halt()` — the smoke can never pass on
//! a half-written disk.
//!
//! ## Guided shell builtins (`disks` / `install` / `netinstall`)
//!
//! docs/installer.md §7.1's interactive path is implemented in
//! `kernel/src/shell.rs` on top of three entry points here:
//!
//! - [`guided_install`] — the offline `install <device> yes`: the same
//!   [`install_payload`] as `INST_OK`, behind a fail-soft pre-flight
//!   (capacity, ISO modules, source volume) so a bad request returns to
//!   the prompt instead of halting,
//! - [`netinstall_run`] — the fallible core `NETINST_OK` also runs
//!   (see there),
//! - and the read-only inventory the shell builds from `ata::list` +
//!   `ahci::list`, which is where the wipe-marker rule is enforced:
//!   **only a disk carrying `reemplazo-target-v1` is ever written**,
//!   with the device line (id, model, size) printed before anything
//!   happens and the literal confirmation `yes` required on top. An
//!   unmarked disk is refused even then — that rule is what lets the
//!   boot proofs stay automatic while a *manual* wipe always needs a
//!   marked disk (AGENTS.md).
//!
//! ## I2b: the real HTTPS source (opt-in, docs/installer.md §8.8)
//!
//! [`netprove_https`] is a **separate, fallible** entry point for real
//! hardware: same DNS → TCP → TLS 1.3 (pinned USERTrust ECC root) →
//! HTTP → ustar → [`install_payload`] chain as the mock, but the
//! payload comes from GitHub over our own stack. It is *not* called by
//! the boot chain — `netprove` (the mock, `NETINST_OK`) stays the CI
//! gate and every marker chain is untouched. Every network/JSON/tar
//! check happens **before** the first disk write: a failed fetch
//! returns an `Err` and the target is untouched.
//!
//! Two source shapes are accepted (both on `api.github.com`, with a
//! `User-Agent` and no credentials):
//!
//! - `…/contents/payload.tar?ref=main` with
//!   `Accept: application/vnd.github.raw` — the **primary** route: one
//!   200 response with `Content-Length`, no redirect, chain ends at the
//!   pinned root (verified live, §8.8);
//! - `…/releases/latest` — the JSON route: a bounded, fail-closed
//!   scan finds the `payload.tar` asset and its `browser_download_url`,
//!   which is validated against a host allowlist before any request.
//!   Release *assets* redirect to
//!   `release-assets.githubusercontent.com` (Let's Encrypt → ISRG Root
//!   X1), so the pinned-root verifier refuses them; the allowlist
//!   rejects that host up front with a clear error instead of silently
//!   connecting somewhere we cannot authenticate.
//!
//! ## What these milestones deliberately do *not* do (later work)
//!
//! - **No automatic real-HTTPS invocation** (the shell/hardware
//!   integrator must opt in — §8.8 gives the exact line), no AHCI
//!   *install* write path yet (the driver exists and probes + reads;
//!   the smoke's install runs on the IDE disk — `AHCI_OK` is the
//!   additive proof), no `/boot/grub/grub.cfg` on p2 (I1b embeds a tiny
//!   early config in `core.img` instead, §8.6), no GRUB modules beyond
//!   the tested boot-critical set, no interactive menu (timeout 0
//!   semantics: boot the only entry), and no second TLS root (which is
//!   what release-asset downloads would need).

use crate::ata;
use crate::clock;
use crate::fs::{BlockDisk, stamp};
use crate::netstack::{OP_DEADLINE_MS, Stack};
use crate::tls::{self, Stream as TlsStream};
use alloc::string::String;
use core::ptr::{addr_of, addr_of_mut};
use embedded_io::Write;
use embedded_tls::TlsError;
use embedded_tls::blocking::{Aes128GcmSha256, TlsConnection};
use gptwire::{Guid, Partition, TYPE_BASIC_DATA, TYPE_BIOS_GRUB};
use multiboot2::BootInformation;
use net::http::{self, ResponseParser};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;
use url::Url;

/// p1 starts at 1 MiB and spans 1 MiB — docs/installer.md §3.2's
/// `bios_grub` row (1 MiB holds `core.img` ≈172 KB with margin; the
/// GRUB manual asks for ≥31 KiB, 1 MiB recommended).
const P1_FIRST_LBA: u64 = 2048;
const P1_LAST_LBA: u64 = 4095;
/// p2 starts at 2 MiB; its last LBA is *not* a constant here — it
/// comes from [`gptwire::usable_range`], the same function the writer
/// uses, so writer and installer cannot disagree.
const P2_FIRST_LBA: u64 = 4096;
/// Refuse anything smaller than this: GPT's fixed layout needs 34
/// sectors of bookkeeping at each end, and p2 must reach FAT16's
/// 4085-cluster window at 512 B/cluster (≈4218 sectors). 16384
/// sectors (8 MiB) leaves comfortable margin; the smoke's target is
/// 64 MiB.
const MIN_TARGET_SECTORS: u64 = 16_384;
/// Byte cap per *offline* payload file — the stack buffer [`prove`]
/// reads into. Bigger files are *refused* (`fat::Error::BufferTooSmall`),
/// never truncated, so a lying directory entry can't overrun anything.
/// (The network path has its own bound: [`DOWNLOAD_CAP`].)
const PAYLOAD_CAP: usize = 4096;
/// Cluster size floor for the installer's formats (see
/// `fat::FormatOpts::min_sectors_per_cluster`): 16 sectors = 8 KiB.
/// With a ~1.7 MB kernel in the payload, first-fit allocation probes
/// the FAT once per cluster — at 1 KiB clusters that is ~1700 scans
/// of a growing prefix (O(n²) sector reads, measured too slow for the
/// smoke budget), at 8 KiB clusters it is ~210.
const MIN_SECTORS_PER_CLUSTER: u32 = 16;
/// The offline payload: read from the source volume (FS1 proven these
/// exact bytes), written to p2, read back byte-exact. Names carry no
/// leading `/` — [`qualify`] adds it (and validates) at use.
const PAYLOAD: [&str; 2] = ["README.TXT", "RESULT.TXT"];
/// Upper bound on files in `payload.tar` (I2) — the fixed array the
/// parser fills, so a hostile archive can never outgrow storage.
const MAX_PAYLOAD_FILES: usize = 8;
/// Installed volume's label/id — fixed, so installs are
/// byte-reproducible (v1 stance, `gptwire`'s docs say the same about
/// the GUIDs).
const VOLUME_LABEL: [u8; 11] = *b"REEMPLAZO  ";
const VOLUME_ID: u32 = 0x2026_1122;
/// Fixed GUIDs (v1: deterministic; per-install randomness is future
/// work — documented in `gptwire`).
const DISK_GUID: Guid = Guid::from_bytes([0xA5; 16]);
const P1_UNIQUE_GUID: Guid = Guid::from_bytes([0xB1; 16]);
const P2_UNIQUE_GUID: Guid = Guid::from_bytes([0xB2; 16]);

// --- I1b: GRUB boot code on the target (docs/installer.md §4, §8.6) -----

/// `boot.img` is one 512-byte MBR sector by construction (GRUB's
/// `grub-bios-setup` refuses any other size).
const GRUB_BOOT_BYTES: usize = 512;
/// Hard cap for `core.img`: p1 is exactly 1 MiB (2048 sectors), the
/// block-list `len` field counts the remaining sectors in 16 bits, and
/// everything must fit the partition whole — so the artifact is bounded
/// by the *consumer* (the installed layout), never by the tag. The
/// measured artifact is ≈148 KiB; drift past 1 MiB is a build error,
/// not a runtime guess.
const GRUB_CORE_CAP: usize = 1 << 20;
/// Hard cap for the whole `grubpayload` module: `boot.img ‖ core.img`.
const GRUB_MODULE_CAP: usize = GRUB_BOOT_BYTES + GRUB_CORE_CAP;
/// Hard cap for the kernel payload module (the offline `/KERNEL.ELF`
/// source). Same bound as the network download ([`DOWNLOAD_CAP`]) and
/// well above the ~2.1 MiB kernel, so build drift fails loudly.
const KERNEL_MODULE_CAP: usize = DOWNLOAD_CAP;

/// `boot.img` field offsets — GRUB 2.12's
/// `include/grub/i386-pc/boot.h`:
/// `GRUB_BOOT_MACHINE_KERNEL_SECTOR = 0x5c` (kernel_sector +
/// kernel_sector_high: `grub-setup`'s `write_rootdev` stores an
/// *unaligned 64-bit* little-endian sector here),
/// `BOOT_DRIVE = 0x64`, `DRIVE_CHECK = 0x66`, `WINDOWS_NT_MAGIC =
/// 0x1b8`, `PART_START = 0x1be`, `PART_END = 0x1fe`, `BPB_START =
/// 0x03`, `BPB_END = 0x5a`.
const GRUB_KERNEL_SECTOR: usize = 0x5c;
const GRUB_BOOT_DRIVE: usize = 0x64;
const GRUB_DRIVE_CHECK: usize = 0x66;
const GRUB_NT_MAGIC: usize = 0x1b8;
const GRUB_PART_START: usize = 0x1be;
const GRUB_PART_END: usize = 0x1fe;
const GRUB_BPB_START: usize = 0x03;
const GRUB_BPB_END: usize = 0x5a;

/// `core.img`'s first sector is GRUB's `diskboot.S`: the block list
/// starts at `512 - sizeof(grub_boot_blocklist)` = **500** and grows
/// *downward*; each entry is `{ u64 start; u16 len; u16 segment }`
/// (absolute disk LBA, sector count, load segment) and a zero-length
/// entry terminates it. The entry before the first one is at 488..500.
/// The default entry's segment is
/// `(GRUB_BOOT_I386_PC_KERNEL_SEG + 0x20) = 0x820` — the value
/// `grub-setup`'s `bl.current_segment` starts from and `diskboot.S`
/// expects to load the rest of core at `0x8200`.
const GRUB_BLOCKLIST: usize = 500;
const GRUB_BLOCKLIST_TERM: usize = 488;
const GRUB_BLOCKLIST_SEGMENT: u16 = 0x0820;

/// The two multiboot2 module command lines the installer ISO's GRUB
/// config attaches (`module2 … grubpayload`, `module2 … payload`), and
/// the only names [`capture_modules`] recognizes.
const GRUB_MODULE_NAME: &str = "grubpayload";
const KERNEL_MODULE_NAME: &str = "payload";

/// Captured `grubpayload` module: `boot.img` then `core.img` (the split
/// is the first [`GRUB_BOOT_BYTES`], §8.6 documents the layout).
/// Single-use statics, written **once** by [`capture_modules`] before
/// `memory::init` and only read afterwards — the `DOWNLOAD`/`VERIFY`
/// idiom.
static mut GRUB_COPY: [u8; GRUB_MODULE_CAP] = [0; GRUB_MODULE_CAP];
/// Captured `payload` module: the running kernel's own ELF file.
static mut KERNEL_COPY: [u8; KERNEL_MODULE_CAP] = [0; KERNEL_MODULE_CAP];

/// What [`capture_modules`] found (lengths into the statics; `0` means
/// the module was absent — a disk-boot of the installed system has no
/// modules at all).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Payloads {
    grub_len: usize,
    kernel_len: usize,
}

impl Payloads {
    /// `(boot.img, core.img)` slices of the captured GRUB module —
    /// `None` when the ISO did not carry it.
    fn grub(&self) -> Option<(&'static [u8], &'static [u8])> {
        if self.grub_len < GRUB_BOOT_BYTES {
            return None;
        }
        // SAFETY: `grub_len` was validated by `mbi::check_module`
        // against `GRUB_MODULE_CAP` and written by `capture_modules`;
        // the static outlives every use (kernel lifetime) and nothing
        // writes it after the copy (single core).
        let all =
            unsafe { core::slice::from_raw_parts(addr_of!(GRUB_COPY) as *const u8, self.grub_len) };
        let (boot, core) = all.split_at(GRUB_BOOT_BYTES);
        Some((boot, core))
    }

    /// The kernel image bytes from the `payload` module, or `None` when
    /// absent (the network path carries its own kernel file instead).
    fn kernel_image(&self) -> Option<&'static [u8]> {
        if self.kernel_len == 0 {
            return None;
        }
        // SAFETY: as `grub()`: validated length, single-use static.
        Some(unsafe {
            core::slice::from_raw_parts(addr_of!(KERNEL_COPY) as *const u8, self.kernel_len)
        })
    }
}

/// Copy the installer's multiboot2 modules into kernel-owned statics.
///
/// Called from `kernel_main` **before `memory::init`**: GRUB's module
/// memory is not listed as reserved in the multiboot2 memory map, so
/// once frames are handed out the module bytes are fair game for the
/// heap/allocator. Copying first (interrupts still off, single core)
/// makes the installer independent of that.
///
/// Bounds: [`mbi::check_module`] validates every range (non-zero start,
/// `end > start`, length ≤ the module's consumer cap) before anything
/// is dereferenced. A module that is *present but malformed or too
/// large* is `FATAL` + `halt()` — it can only be a broken ISO build,
/// never boot noise. Unknown module names are ignored (GRUB may pass
/// other files); duplicates of a recognized name are refused so the
/// installer can never pick one of two.
pub(crate) fn capture_modules(info: &BootInformation) -> Payloads {
    let mut payloads = Payloads {
        grub_len: 0,
        kernel_len: 0,
    };
    for tag in info.module_tags() {
        let Ok(name) = tag.cmdline() else {
            continue; // no command line → not one of ours
        };
        let cap = match name {
            GRUB_MODULE_NAME => GRUB_MODULE_CAP,
            KERNEL_MODULE_NAME => KERNEL_MODULE_CAP,
            _ => continue,
        };
        let len = match mbi::check_module(tag.start_address(), tag.end_address(), cap) {
            Ok(len) => len,
            Err(e) => {
                serial_println!("FATAL: mbi: module range refused: {:?}", e);
                crate::halt();
            }
        };
        let already = if name == GRUB_MODULE_NAME {
            payloads.grub_len != 0
        } else {
            payloads.kernel_len != 0
        };
        if already {
            serial_println!("FATAL: mbi: duplicate module (same command line twice)");
            crate::halt();
        }
        let dst = if name == GRUB_MODULE_NAME {
            addr_of_mut!(GRUB_COPY) as *mut u8
        } else {
            addr_of_mut!(KERNEL_COPY) as *mut u8
        };
        // SAFETY: `check_module` proved `start != 0`, `end > start`, and
        // `len <= cap` (the destination static's length). Both halves
        // are the multiboot2 ABI's 32-bit physical addresses, inside
        // `entry.S`'s identity map. The destination is this function's
        // single-use static and no other writer exists; interrupts are
        // still off and the machine is single-core during boot.
        unsafe { core::ptr::copy_nonoverlapping(tag.start_address() as *const u8, dst, len) };
        if name == GRUB_MODULE_NAME {
            payloads.grub_len = len;
        } else {
            payloads.kernel_len = len;
        }
    }
    // One line, numbers only (the command lines / lengths come from the
    // bootloader; never print the strings raw).
    if payloads.grub_len != 0 || payloads.kernel_len != 0 {
        serial_println!(
            "mbi: module payloads captured: grub {} B, kernel {} B",
            payloads.grub_len,
            payloads.kernel_len
        );
    }
    payloads
}

// --- I2: the payload download -------------------------------------------

/// Payload URL — plain HTTP on the slirp gateway: xtask's in-container
/// `nc` responder listens on the *container's* loopback `:8080`
/// (guest→`10.0.2.2:8080` lands there, exactly like the chat mock on
/// `:8099`; docs §7.2). IP taken from `net::SLIRP_GATEWAY`, never
/// re-typed by hand.
const PAYLOAD_PORT: u16 = 8080;
const PAYLOAD_PATH: &str = "/payload.tar";
/// [`Stack`]'s fifth TCP socket + its local port — the `apps::ai`
/// exchange owns `tcp5`/49163 and leaves it TimeWait/Closed (what
/// `connect` accepts, `ai.rs`'s documented observation), so the
/// payload GET reuses it the same way the `ai` builtin does.
const PAYLOAD_HANDLE_LOCAL_PORT: u16 = 49163;
/// Byte bound on the whole download — the `payload.tar` the builder
/// emits is kernel + a README; the kernel has grown past 2 MiB with
/// the browser/AI/TUI milestones (≈2.06 MB at the time of writing), so
/// the cap is 4 MiB: still a refusal (never a truncation) for a
/// hostile or misbehaving server, with headroom for further growth
/// before this needs revisiting.
const DOWNLOAD_CAP: usize = 4 * 1024 * 1024;
/// Per-read staging for `ResponseParser::feed` — the `ai.rs`
/// `SCRATCH` value (feed requires `body_out ≥ input.len()`).
const NET_SCRATCH: usize = 1460;
/// Connect/send/read deadlines: the read gets three [`OP_DEADLINE_MS`]
/// windows because it moves ~1.7 MB through a 4 KiB socket buffer;
/// still bounded, still far inside the smoke's total budget.
const NET_DEADLINE_MS: u64 = OP_DEADLINE_MS * 3;

/// The downloaded `payload.tar` — streamed here by [`download`],
/// parsed in place by [`parse_tar`]. Single-use static (the `tls.rs`/
/// `ai.rs` `READ_STORAGE` idiom): written only from `netprove` on the
/// single core; the PIT handler never touches it.
static mut DOWNLOAD: [u8; DOWNLOAD_CAP] = [0; DOWNLOAD_CAP];
/// Read-back scratch for [`install_payload`]'s byte-exact verify — a
/// second buffer because the network path's *source* bytes live in
/// [`DOWNLOAD`] and must survive the comparison (the offline path
/// could use its stack buffers, but one uniform `verify` parameter
/// keeps the proof identical for both).
static mut VERIFY: [u8; DOWNLOAD_CAP] = [0; DOWNLOAD_CAP];
/// The payload HTTP parser (`net::http::ResponseParser` is ~8 KiB —
/// static, never on the boot stack; `reset()` per response like every
/// other sequential exchange in the kernel).
static mut NET_PARSER: ResponseParser = ResponseParser::new();
/// Per-read staging for `ResponseParser::feed` (see `ai.rs`'s
/// `STAGING`): `feed` writes into `body_out` from here, then the bytes
/// are appended to [`DOWNLOAD`].
static mut NET_STAGING: [u8; NET_SCRATCH] = [0; NET_SCRATCH];
/// Serialized GET request.
static mut NET_REQ: [u8; 256] = [0; 256];

// --- I2b: real HTTPS source (opt-in; docs/installer.md §8.8) --------------

/// The real payload URL the hardware/shell integrator should pass to
/// [`netprove_https`]: GitHub's *contents* API with the raw media type
/// (§6.2 v1). Verified live 2026-11-22: `200`,
/// `Content-Type: application/vnd.github.raw`, `Content-Length` set and
/// **no redirect** — the only shape whose chain terminates at our
/// single pinned USERTrust ECC root. `?ref=main` is required: without
/// it the API answers 404 for this repository (verified live).
///
/// A `payload.tar` file must actually be published at that path before
/// a real fetch can succeed; until then the function returns a clear
/// `HTTP 404` error and touches no disk.
// Opt-in path: the shell/hardware integrator passes this URL (docs §8.8).
#[allow(dead_code)]
pub const NETINSTALL_REAL_URL: &str =
    "https://api.github.com/repos/LuisErnestoZamb/reemplazo/contents/payload.tar?ref=main";
/// The only host allowed to *start* a real install (metadata or raw).
const GITHUB_API_HOST: &str = "api.github.com";
/// Asset name looked up in `releases/latest`.
const RELEASE_ASSET_NAME: &str = "payload.tar";
/// Fixed request headers: no credentials, ever (§8.8).
const USER_AGENT: &str = "User-Agent: reemplazo-netinstall/0.1";
const ACCEPT_JSON: &str = "Accept: application/vnd.github+json";
const ACCEPT_RAW: &str = "Accept: application/vnd.github.raw";
const API_VERSION: &str = "X-GitHub-Api-Version: 2022-11-28";
/// Bound on the release-metadata JSON body. A bigger response is
/// refused, never truncated (the asset list in this repo is tiny).
const JSON_CAP: usize = 128 * 1024;
/// Bounds for the bounded JSON scanner and the HTTPS exchange statics.
const JSON_KEY_CAP: usize = 64;
const JSON_NAME_CAP: usize = 128;
const JSON_URL_CAP: usize = 512;
const JSON_DEPTH_CAP: u8 = 32;
const HTTPS_REQ_CAP: usize = 1024;
const HTTPS_LOC_CAP: usize = 512;
const MAX_HTTPS_HOPS: usize = 3; // first request + at most two redirects

/// Single-use statics for the real-HTTPS path (the `tls.rs`/`ai.rs`
/// `READ_STORAGE` idiom): written only by [`netprove_https`], on the
/// single core, sequentially; the PIT handler never touches them.
static mut JSON_BUF: [u8; JSON_CAP] = [0; JSON_CAP];
static mut ASSET_URL: [u8; JSON_URL_CAP] = [0; JSON_URL_CAP];
static mut HTTPS_PARSER: ResponseParser = ResponseParser::new();
static mut HTTPS_STAGING: [u8; NET_SCRATCH] = [0; NET_SCRATCH];
static mut HTTPS_REQ: [u8; HTTPS_REQ_CAP] = [0; HTTPS_REQ_CAP];
static mut HTTPS_LOC: [u8; HTTPS_LOC_CAP] = [0; HTTPS_LOC_CAP];

/// One payload file: `name` is the archive's bare file name (no
/// leading `/` — [`qualify`] validates and prefixes it), `data` the
/// bytes to install (a stack slice offline, a `&'static` slice of
/// [`DOWNLOAD`] on the network path).
#[derive(Debug, Clone, Copy)]
struct PayloadFile<'a> {
    name: &'a str,
    data: &'a [u8],
}

/// Turn a bare name into the absolute path FAT needs, validating
/// first: non-empty, ≤100 bytes (the tar name field), no `/` (v1
/// installs payload files at the volume root — subdirectories would
/// need `mkdir`, which `fat` does not have), ASCII only (the buffer
/// is bytes; FAT is ASCII). Refuses — never mangles.
fn qualify<'a>(name: &str, out: &'a mut [u8; 101]) -> Result<&'a str, fat::Error> {
    if name.is_empty() || name.len() > 100 || name.contains('/') || !name.is_ascii() {
        return Err(fat::Error::InvalidName);
    }
    out[0] = b'/';
    out[1..1 + name.len()].copy_from_slice(name.as_bytes());
    core::str::from_utf8(&out[..1 + name.len()]).map_err(|_| fat::Error::InvalidName)
}

/// Whole-disk adapter for `gptwire` — sector reads/writes straight
/// through the ATA driver, same contract as `fs::AtaDisk` (aligned
/// whole sectors, range-checked against IDENTIFY capacity on *both*
/// ends: this adapter checks the request, `Drive::*_sectors` re-checks
/// it device-side).
struct GptDev<'a>(&'a ata::Disk);

impl gptwire::Device for GptDev<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors()) * 512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), gptwire::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(gptwire::Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(gptwire::Error::OutOfRange)?;
        if end > self.size_bytes() {
            return Err(gptwire::Error::OutOfRange);
        }
        let lba = u32::try_from(offset / 512).map_err(|_| gptwire::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(gptwire::Error::Read)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), gptwire::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(gptwire::Error::OutOfRange);
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or(gptwire::Error::OutOfRange)?;
        if end > self.size_bytes() {
            return Err(gptwire::Error::OutOfRange);
        }
        let lba = u32::try_from(offset / 512).map_err(|_| gptwire::Error::OutOfRange)?;
        if self.0.write_sectors(lba, buf) {
            Ok(())
        } else {
            Err(gptwire::Error::Write)
        }
    }
}

/// One GPT partition (a byte window) as a `fat::BlockDevice`: byte
/// offsets are partition-relative, every range checked against the
/// window with `fat::checked_end` before the LBA is computed (and the
/// drive re-checks against IDENTIFY capacity, `Drive::*_sectors`'
/// bound).
struct Part<'a>(
    &'a ata::Disk,
    /* first byte */ u64,
    /* bytes */ u64,
);

impl fat::BlockDevice for Part<'_> {
    fn size_bytes(&self) -> u64 {
        self.2
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.2, offset, buf.len())?;
        let abs = self.1.checked_add(offset).ok_or(fat::Error::OutOfRange)?;
        let lba = u32::try_from(abs / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Read)
        }
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.2, offset, buf.len())?;
        let abs = self.1.checked_add(offset).ok_or(fat::Error::OutOfRange)?;
        let lba = u32::try_from(abs / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.write_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Write)
        }
    }
}

/// The window describing p2 on `target` — one value built from the
/// validated GPT and reused for format, copy and verify (so all three
/// steps address the *same* byte range by construction).
fn p2_window(target: &ata::Disk, first_lba: u64, last_lba: u64) -> Part<'_> {
    let bytes = (last_lba - first_lba + 1) * 512;
    Part(target, first_lba * 512, bytes)
}

/// Capacity check shared by every install path (the boot proofs and the
/// shell's guided builtins): the layout needs GPT's fixed bookkeeping at
/// both ends and p2 must reach FAT16's cluster window — see
/// [`MIN_TARGET_SECTORS`]. Returns the refusal message instead of
/// printing it, so the boot proofs turn it into `FATAL:` + halt (via
/// [`prepare`]) and the shell prints it and returns to the prompt.
fn check_size(target: &ata::Disk) -> Result<(), alloc::string::String> {
    let total = u64::from(target.sectors());
    if total < MIN_TARGET_SECTORS {
        return Err(alloc::format!(
            "target too small ({total} sectors, need {MIN_TARGET_SECTORS})"
        ));
    }
    Ok(())
}

/// [`check_size`] plus the one target report line the boot proofs print
/// before any write (byte-identical to I1/I2's output). Fail-closed: a
/// too-small target is `Err`, never a guess.
fn prepare(target: &ata::Disk) -> Result<(), alloc::string::String> {
    check_size(target)?;
    let total = u64::from(target.sectors());
    let mut name_buf = [0u8; 40];
    let model = target.model_name(&mut name_buf);
    serial_println!(
        "install: target {transport} '{model}' {total} sectors ({} MiB)",
        total / 2048,
        transport = target.transport()
    );
    Ok(())
}

/// Validate the install target (shared by [`prove`] and [`netprove`]):
/// the marked second disk, big enough for the layout. `None`
/// (silently — the caller returns without a word) when there is no
/// marked target; `FATAL:` + halt when one exists but is too small to
/// install onto. The probing itself happens **once in `kernel_main`**
/// (before the offline install rewrites LBA0 and erases the marker) —
/// this function only checks and reports.
fn prepare_target(target: Option<&ata::Disk>) -> Option<&ata::Disk> {
    let target = target?;
    if let Err(e) = prepare(target) {
        fatal_msg(&e);
    }
    Some(target)
}

/// The shared install: GPT → format p2 → copy `files` → byte-exact
/// re-read → GRUB boot code last (the commit point). Any failure with a
/// target present is `FATAL: install:` + halt — both markers stand on
/// this one path, so `INST_OK` and `NETINST_OK` assert identical disk
/// work (including an identical, bootable GRUB installation).
fn install_payload(target: &ata::Disk, files: &[PayloadFile<'_>], payloads: &Payloads) {
    // --- Step 1: GPT (docs/installer.md §3.2) ---
    let total = u64::from(target.sectors());
    let Some((_, last_usable)) = gptwire::usable_range(total * 512) else {
        fatal_msg("target cannot hold a GPT");
    };
    if P2_FIRST_LBA > last_usable {
        fatal_msg("target cannot hold the p1+p2 layout");
    }
    let layout = [
        match Partition::new(TYPE_BIOS_GRUB, P1_UNIQUE_GUID, P1_FIRST_LBA, P1_LAST_LBA)
            .with_name(b"BIOSGRUB")
        {
            Ok(p) => p,
            Err(e) => fatal(e),
        },
        match Partition::new(TYPE_BASIC_DATA, P2_UNIQUE_GUID, P2_FIRST_LBA, last_usable)
            .with_name(b"REEMPLAZO")
        {
            Ok(p) => p,
            Err(e) => fatal(e),
        },
    ];
    let dev = GptDev(target);
    if let Err(e) = gptwire::write(&dev, DISK_GUID, &layout) {
        fatal(e);
    }
    // Re-read through the adversarially-tested parser: the marker
    // asserts the *device's* state, not our intent.
    let gpt = match gptwire::read(&dev) {
        Ok(g) => g,
        Err(e) => fatal(e),
    };
    let p2 = gpt
        .partitions()
        .iter()
        .find(|p| p.type_guid == TYPE_BASIC_DATA)
        .copied();
    let Some(p2) = p2 else {
        fatal_msg("p2 missing from the freshly written GPT");
    };
    if p2.first_lba != P2_FIRST_LBA || p2.last_lba != last_usable {
        fatal_msg("p2 bounds on disk differ from the layout");
    }
    serial_println!(
        "install: GPT ok ({} partitions, p2 {}..{})",
        gpt.partitions().len(),
        p2.first_lba,
        p2.last_lba
    );

    // --- Step 2: format p2 as FAT16 (shared formatter) ---
    let part = p2_window(target, p2.first_lba, p2.last_lba);
    let hidden = match u32::try_from(p2.first_lba) {
        Ok(h) => h,
        Err(_) => fatal_msg("p2 start does not fit the BPB hidden-sectors field"),
    };
    let geo = match fat::format_fat16(
        &part,
        &fat::FormatOpts {
            label: &VOLUME_LABEL,
            volume_id: VOLUME_ID,
            hidden_sectors: hidden,
            // 8 KiB clusters: quarters the writer's first-fit FAT
            // probes per allocated cluster — what keeps the ~1.7 MB
            // kernel payload's chain growth inside the smoke budget
            // (module docs, `MIN_SECTORS_PER_CLUSTER`).
            min_sectors_per_cluster: MIN_SECTORS_PER_CLUSTER,
        },
    ) {
        Ok(g) => g,
        Err(e) => fatal(e),
    };
    serial_println!(
        "install: FAT16 formatted ({} clusters x {} B)",
        geo.clusters,
        geo.sectors_per_cluster * 512
    );

    // --- Step 3: copy the payload (one fresh mount, write-through) ---
    {
        let dst = match fat::Fat16::mount(&part) {
            Ok(fs) => fs,
            Err(e) => fatal(e),
        };
        let stamp = stamp();
        for file in files {
            let mut path = [0u8; 101];
            let path = match qualify(file.name, &mut path) {
                Ok(p) => p,
                Err(e) => fatal(e),
            };
            if let Err(e) = dst.write_file(path, file.data, stamp) {
                fatal(e);
            }
        }
    }
    serial_println!("install: copied {} files", files.len());

    // --- Step 4: re-mount p2 from scratch, read back byte-exact ---
    // Fresh `Part` + fresh `fat::Fat16`: no state from the writes
    // survives, so the read-back can only come from the device (the
    // FS2 proof shape, applied to the installed volume). `verify` is
    // the caller's scratch — big enough for its own files by
    // construction (offline: 4 KiB files; network: ≤ DOWNLOAD_CAP).
    let verify_part = p2_window(target, p2.first_lba, p2.last_lba);
    let vfs = match fat::Fat16::mount(&verify_part) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };
    for file in files {
        let mut path = [0u8; 101];
        let path = match qualify(file.name, &mut path) {
            Ok(p) => p,
            Err(e) => fatal(e),
        };
        if file.data.len() > VERIFY_LEN {
            fatal_msg("verify scratch smaller than a payload file");
        }
        // SAFETY: single-use static (module note); bounded by the
        // length check above, and only ever read back through `vfs`.
        let scratch = unsafe { &mut *addr_of_mut!(VERIFY) };
        let n = match vfs.read_file(path, scratch) {
            Ok(n) => n,
            Err(e) => fatal(e),
        };
        if n != file.data.len() || scratch[..n] != *file.data {
            serial_println!(
                "FATAL: install: {} read back {} bytes, expected exactly {}",
                path,
                n,
                file.data.len()
            );
            crate::halt();
        }
    }

    // --- Step 5: GRUB boot code (I1b) — the commit point, last ---
    install_grub(target, payloads);
}

/// Write GRUB's `boot.img` + `core.img` onto the freshly installed
/// target, replicating `grub-bios-setup`'s BIOS-on-GPT sequence
/// (docs/installer.md §4/§8.6):
///
/// 1. **`core.img` → p1 (`bios_grub`, LBA 2048), whole.** The first
///    sector is GRUB's `diskboot`; its block list is *recomputed* here
///    (never trusted from the artifact): the range is contiguous, so one
///    entry `{ start = p1_first + 1, len = core_sectors - 1,
///    segment = 0x820 }` plus the zero terminator is exactly what
///    `grub-setup` emits for a contiguous embedding, and the same
///    position `grub-setup` patches (`core_img + 512 - 12`).
/// 2. **`boot.img` → LBA0.** Preserve what `grub-setup` preserves — the
///    DOS BPB area (`0x03..0x5a`) and the Windows-NT magic + disk
///    signature + partition table (`0x1b8..0x1fe`, which is where the
///    GPT protective MBR entry lives) — then patch
///    `GRUB_BOOT_MACHINE_KERNEL_SECTOR` (unaligned u64 LE) with p1's
///    first LBA, force `boot_drive = 0xFF`, and apply the hard-disk
///    drive-check workaround (`0x66..0x68` = `nop; nop`) exactly as
///    `grub-setup` does for a non-floppy destination.
/// 3. **Read both back** and compare byte-exact, then require the
///    protective MBR's `0xEE` record and `55 AA` signature still parse
///    — the marker asserts the device, not our intent.
///
/// The installed `core.img` embeds an early config that searches for
/// `/KERNEL.ELF` and boots it with `multiboot2` (§8.6 documents the
/// exact config), so p2 needs no `/boot/grub` directory at all.
fn install_grub(target: &ata::Disk, payloads: &Payloads) {
    let Some((boot, core)) = payloads.grub() else {
        fatal_msg("grubpayload module missing (ISO built without GRUB artifacts?)");
    };
    if boot.len() != GRUB_BOOT_BYTES
        || boot.first() != Some(&0xEB)
        || boot.get(510..512) != Some(&[0x55, 0xAA][..])
    {
        fatal_msg("grubpayload: boot.img is not a GRUB MBR sector");
    }
    // Non-empty, fits p1, and is really GRUB's diskboot sector: the
    // block-list terminator + default segment are fixed artifacts.
    if core.len() < 2 * 512 || core.len() > GRUB_CORE_CAP {
        fatal_msg("grubpayload: core.img size out of range");
    }
    if core[GRUB_BLOCKLIST_TERM..GRUB_BLOCKLIST] != [0u8; 12] {
        fatal_msg("grubpayload: core.img has no block-list terminator");
    }
    if core[510..512] != GRUB_BLOCKLIST_SEGMENT.to_le_bytes() {
        fatal_msg("grubpayload: core.img is not a diskboot image");
    }
    let core_sectors = core.len().div_ceil(512);
    let p1_sectors = P1_LAST_LBA - P1_FIRST_LBA + 1;
    if core_sectors as u64 > p1_sectors || core_sectors < 2 {
        fatal_msg("grubpayload: core.img does not fit the bios_grub partition");
    }
    // `len` counts the sectors after the first; p1's 2048 sectors keep
    // this far below u16::MAX (asserted by the fit check above).
    let rest = match u16::try_from(core_sectors - 1) {
        Ok(n) => n,
        Err(_) => fatal_msg("grubpayload: core.img block list too long"),
    };

    // (1) core.img: first sector patched, the rest written as-is.
    let mut first = [0u8; 512];
    first.copy_from_slice(&core[..512]);
    first[GRUB_BLOCKLIST_TERM..GRUB_BLOCKLIST].fill(0); // terminator
    first[GRUB_BLOCKLIST..GRUB_BLOCKLIST + 8].copy_from_slice(&(P1_FIRST_LBA + 1).to_le_bytes());
    first[GRUB_BLOCKLIST + 8..GRUB_BLOCKLIST + 10].copy_from_slice(&rest.to_le_bytes());
    first[GRUB_BLOCKLIST + 10..GRUB_BLOCKLIST + 12]
        .copy_from_slice(&GRUB_BLOCKLIST_SEGMENT.to_le_bytes());
    if !write_sectors_at(target, P1_FIRST_LBA, &first) {
        fatal_msg("writing core.img's first sector to p1");
    }
    let body = &core[512..];
    let full = body.len() / 512 * 512;
    if full > 0 && !write_sectors_at(target, P1_FIRST_LBA + 1, &body[..full]) {
        fatal_msg("writing core.img to p1");
    }
    let tail = &body[full..];
    if !tail.is_empty() {
        let mut pad = [0u8; 512];
        pad[..tail.len()].copy_from_slice(tail);
        if !write_sectors_at(target, P1_FIRST_LBA + 1 + (full / 512) as u64, &pad) {
            fatal_msg("writing core.img's tail to p1");
        }
    }

    // (2) boot.img → LBA0, preserving what grub-setup preserves.
    let mut mbr = [0u8; 512];
    if !target.read_sectors(0, &mut mbr) {
        fatal_msg("reading LBA0 before writing boot.img");
    }
    let mut out = [0u8; 512];
    out.copy_from_slice(boot);
    out[GRUB_BPB_START..GRUB_BPB_END].copy_from_slice(&mbr[GRUB_BPB_START..GRUB_BPB_END]);
    out[GRUB_NT_MAGIC..GRUB_PART_END].copy_from_slice(&mbr[GRUB_NT_MAGIC..GRUB_PART_END]);
    out[GRUB_KERNEL_SECTOR..GRUB_KERNEL_SECTOR + 8].copy_from_slice(&P1_FIRST_LBA.to_le_bytes());
    out[GRUB_BOOT_DRIVE] = 0xFF;
    out[GRUB_DRIVE_CHECK] = 0x90; // nop out the jmp → run the hard-disk
    out[GRUB_DRIVE_CHECK + 1] = 0x90; // drive-number workaround
    if !target.write_sectors(0, &out) {
        fatal_msg("writing boot.img to LBA0");
    }

    // (3) Read back: LBA0 byte-exact, p1's first sector byte-exact, and
    // the protective MBR still valid (0xEE type + 55 AA signature).
    let mut check = [0u8; 512];
    if !target.read_sectors(0, &mut check) || check != out {
        fatal_msg("boot.img read back from LBA0 differs");
    }
    if check[GRUB_PART_START + 4] != 0xEE || check[510..512] != [0x55, 0xAA] {
        fatal_msg("protective MBR is no longer valid after boot.img");
    }
    let mut check_core = [0u8; 512];
    if !target.read_sectors(P1_FIRST_LBA as u32, &mut check_core) || check_core != first {
        fatal_msg("core.img's first sector read back from p1 differs");
    }
    serial_println!(
        "install: GRUB on disk (boot.img {} B at LBA0, core.img {} B at LBA {})",
        GRUB_BOOT_BYTES,
        core.len(),
        P1_FIRST_LBA
    );
}

/// Write whole sectors at `lba` in ≤256-sector commands (the ATA
/// driver's documented per-command bound), range-checked first.
fn write_sectors_at(target: &ata::Disk, lba: u64, bytes: &[u8]) -> bool {
    const CHUNK: usize = 256 * 512;
    if bytes.is_empty() || !bytes.len().is_multiple_of(512) {
        return false;
    }
    let mut off = 0usize;
    while off < bytes.len() {
        let n = (bytes.len() - off).min(CHUNK);
        let Ok(lba) = u32::try_from(lba + (off / 512) as u64) else {
            return false;
        };
        if !target.write_sectors(lba, &bytes[off..off + n]) {
            return false;
        }
        off += n;
    }
    true
}

/// Length of the [`VERIFY`] scratch, checked against every payload
/// file before the read-back (a file bigger than the scratch is a
/// `FATAL`, never a truncated "pass").
const VERIFY_LEN: usize = DOWNLOAD_CAP;

/// Why assembling the offline payload file list failed. Kept separate
/// from [`fatal`] so the boot proof can print exactly what it always
/// printed while the shell's guided `install` reports the same refusal
/// as a soft error (return to the prompt, nothing written).
#[derive(Debug, Clone, Copy)]
enum OfflineError {
    /// The ISO carried no `payload` module — without the kernel image
    /// the installed disk would not boot, so the install is refused
    /// before the first write.
    NoKernel,
    /// The source volume refused to mount, or a payload file could not
    /// be read (bounded by [`PAYLOAD_CAP`]: too big is refused, never
    /// truncated).
    Fat(fat::Error),
}

/// The offline payload file list — `/README.TXT` + `/RESULT.TXT` read
/// from the source volume (the FS1 machinery, bounded by
/// [`PAYLOAD_CAP`]) and `/KERNEL.ELF` from the ISO's `payload` module
/// (I1b: the running kernel's own ELF bytes, so the installed disk
/// boots standalone even offline).
///
/// Shared by [`prove`] (boot) and [`guided_install`] (shell), so both
/// install the same files. Refusals are returned, not printed: [`prove`]
/// turns them into the `FATAL: install: …` + halt it always had, the
/// shell into a line and a fresh prompt.
fn offline_files<'a>(
    source: &ata::Disk,
    payloads: &Payloads,
    readme: &'a mut [u8; PAYLOAD_CAP],
    result: &'a mut [u8; PAYLOAD_CAP],
) -> Result<[PayloadFile<'a>; 3], OfflineError> {
    let kernel = payloads.kernel_image().ok_or(OfflineError::NoKernel)?;

    let src_disk = BlockDisk(source);
    let src_fs = match fat::Fat16::mount(&src_disk) {
        Ok(fs) => fs,
        Err(e) => return Err(OfflineError::Fat(e)),
    };
    let n_readme = read_named(&src_fs, PAYLOAD[0], readme).map_err(OfflineError::Fat)?;
    let n_result = read_named(&src_fs, PAYLOAD[1], result).map_err(OfflineError::Fat)?;
    // The reads are done; the buffers are handed to the returned list
    // for its whole lifetime (the caller keeps them alive on its stack
    // for exactly as long as `files` lives).
    let readme: &'a [u8] = readme;
    let result: &'a [u8] = result;
    Ok([
        PayloadFile {
            name: PAYLOAD[0],
            data: &readme[..n_readme],
        },
        PayloadFile {
            name: PAYLOAD[1],
            data: &result[..n_result],
        },
        PayloadFile {
            // 8.3, uppercase: the path core.img's embedded config opens.
            name: "KERNEL.ELF",
            data: kernel,
        },
    ])
}

/// Offline install (I1): read the payload from the source volume, add
/// the ISO's `payload` module as `/KERNEL.ELF`, run [`install_payload`],
/// print `INST_OK`. Silent without a marked target disk; `FATAL:` +
/// `halt()` on any failure with one.
pub(crate) fn prove(source: &ata::Disk, target: Option<&ata::Disk>, payloads: &Payloads) {
    let Some(target) = prepare_target(target) else {
        return; // no (marked) target disk → zero output, boot continues
    };
    let mut first = [0u8; PAYLOAD_CAP];
    let mut second = [0u8; PAYLOAD_CAP];
    let files = match offline_files(source, payloads, &mut first, &mut second) {
        Ok(files) => files,
        // Same two refusals, same messages and same order as before
        // this was factored out (the module check came first).
        Err(OfflineError::NoKernel) => {
            fatal_msg("payload module missing (installed disk would not boot)")
        }
        Err(OfflineError::Fat(e)) => fatal(e),
    };

    install_payload(target, &files, payloads);
    serial_println!("INST_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// The guided shell `install <device> yes` builtin (docs/installer.md
/// §7.1): the *same* [`install_payload`] the boot proofs run — GPT →
/// format p2 → copy → byte-exact re-read → GRUB last — reached through
/// a fail-soft pre-flight instead of `FATAL:` + halt:
///
/// 1. capacity ([`check_size`]),
/// 2. the installer ISO's modules (`grubpayload` for GRUB's boot code,
///    `payload` for `/KERNEL.ELF`) — without them the installed disk
///    would not boot, so the request is refused *before* any write,
/// 3. the source volume, when one is attached: [`offline_files`] reads
///    the same `/README.TXT` + `/RESULT.TXT` [`prove`] copies; with no
///    source (the real-hardware case: DVD ISO + empty disk) only
///    `/KERNEL.ELF` goes to p2, which is all the boot path needs.
///
/// Every refusal here is an `Err` the shell prints and returns from —
/// the builtin never halts the machine. Once [`install_payload`] starts
/// writing, a disk failure stays `FATAL:` + halt exactly like the boot
/// proof: a half-written target must never look like a success (the
/// wipe marker already guaranteed the disk *may* be written).
pub(crate) fn guided_install(
    target: &ata::Disk,
    payloads: &Payloads,
    source: Option<&ata::Disk>,
) -> Result<(), alloc::string::String> {
    check_size(target)?;
    if payloads.grub().is_none() {
        return Err(alloc::string::String::from(
            "no GRUB artifacts captured (boot the installer ISO, not the installed system)",
        ));
    }

    let mut first = [0u8; PAYLOAD_CAP];
    let mut second = [0u8; PAYLOAD_CAP];
    let mut files = [PayloadFile {
        name: "",
        data: &[],
    }; 3];
    let count = match source {
        Some(source) => match offline_files(source, payloads, &mut first, &mut second) {
            Ok(list) => {
                files = list;
                list.len()
            }
            Err(OfflineError::NoKernel) => {
                return Err(alloc::string::String::from(
                    "payload module missing (installed disk would not boot)",
                ));
            }
            Err(OfflineError::Fat(e)) => return Err(source_error(e)),
        },
        None => {
            // No source volume: the kernel image alone makes the disk
            // bootable (I1b's early GRUB config only opens /KERNEL.ELF).
            let Some(kernel) = payloads.kernel_image() else {
                return Err(alloc::string::String::from(
                    "payload module missing (boot the installer ISO, not the installed system)",
                ));
            };
            files[0] = PayloadFile {
                name: "KERNEL.ELF",
                data: kernel,
            };
            1
        }
    };

    install_payload(target, &files[..count], payloads);
    Ok(())
}

/// A source-volume refusal as the shell prints it — the two cases a
/// user can actually fix get plain text, everything else keeps the
/// `fat::Error` name (fail-closed, no guessing).
fn source_error(e: fat::Error) -> alloc::string::String {
    match e {
        fat::Error::NotFound => alloc::string::String::from(
            "source volume is missing README.TXT or RESULT.TXT — refusing a partial install",
        ),
        fat::Error::BufferTooSmall => alloc::string::String::from(
            "a payload file on the source volume is larger than the install bound",
        ),
        other => alloc::format!("source volume refused: {other:?}"),
    }
}

/// Read `name` (bare, [`qualify`]-prefixed) from a mounted volume
/// into `buf` — the offline path's bounded source read.
fn read_named(
    fs: &fat::Fat16<'_, BlockDisk<'_>>,
    name: &str,
    buf: &mut [u8],
) -> Result<usize, fat::Error> {
    let mut path = [0u8; 101];
    let path = qualify(name, &mut path)?;
    fs.read_file(path, buf)
}

// ---------------------------------------------------------------------------
// I2: network installer
// ---------------------------------------------------------------------------

/// Network install (`NETINST_OK`): acquire the target, fetch
/// `payload.tar` over our own stack, walk it, run the same
/// [`install_payload`], print `NETINST_OK`. Requires the NIC (called
/// after the boot network chain) and a *marked* target — silent
/// otherwise, like every other proof here.
///
/// The boot contract is unchanged: every refusal still ends in
/// `FATAL: install: …` + halt, with the same messages I2 always
/// printed. The fallible core the shell's `netinstall` builtin shares
/// is [`netinstall_run`].
pub(crate) fn netprove(stack: &mut Stack, target: Option<&ata::Disk>, payloads: &Payloads) {
    let Some(target) = target else {
        return; // no marked target → no network noise either
    };
    // Report line first, exactly where `prepare_target` printed it
    // (before `netinstall: GET …`), then the install itself.
    if let Err(e) = prepare(target) {
        fatal_msg(&e);
    }
    if let Err(e) = netinstall_run(stack, target, payloads) {
        fatal_msg(&e);
    }
    serial_println!("NETINST_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// The fallible core of the network install — [`netprove`] above and
/// the shell's `netinstall <device> yes` builtin (docs/installer.md
/// §7.1) run exactly this: capacity + module pre-flight (soft `Err`,
/// nothing written), then the `payload.tar` download over our own
/// stack, the ustar walk, and the same [`install_payload`] as `INST_OK`
/// and the guided `install`. [`netprove`] wraps it with `FATAL:` +
/// halt so the boot chain's fail-closed contract is untouched; the
/// shell prints the `Err` and returns to the prompt. A *disk* failure
/// inside [`install_payload`] still halts — see [`guided_install`].
pub(crate) fn netinstall_run(
    stack: &mut Stack,
    target: &ata::Disk,
    payloads: &Payloads,
) -> Result<(), alloc::string::String> {
    check_size(target)?;
    if payloads.grub().is_none() {
        return Err(alloc::string::String::from(
            "no GRUB artifacts captured (boot the installer ISO, not the installed system)",
        ));
    }

    let gw = net::SLIRP_GATEWAY;
    let host = alloc::format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
    serial_println!("netinstall: GET {host}:{PAYLOAD_PORT}{PAYLOAD_PATH}");
    let n = download(stack, &host).map_err(alloc::string::String::from)?;
    serial_println!("netinstall: {n} bytes received");

    // SAFETY: `download` wrote exactly `n` bytes into the single-use
    // static (module note); `n ≤ DOWNLOAD_CAP` is its contract.
    let archive: &'static [u8] =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(DOWNLOAD) as *const u8, n) };
    let mut files = [PayloadFile {
        name: "",
        data: &[],
    }; MAX_PAYLOAD_FILES];
    let count = parse_tar(archive, &mut files).map_err(alloc::string::String::from)?;
    serial_println!("netinstall: payload carries {count} files");

    install_payload(target, &files[..count], payloads);
    Ok(())
}

/// Fetch the whole `payload.tar` into [`DOWNLOAD`] over `tcp5` —
/// plain HTTP GET (no DNS: `host` is the dotted quad from
/// `net::SLIRP_GATEWAY`), framed incrementally by
/// [`ResponseParser`] into [`NET_STAGING`], appended to the static.
/// Returns the byte count. Every failure is an `Err(&'static str)`
/// (the caller turns it into `FATAL:` + halt); the socket is torn
/// down (RST) on error so a failed install cannot wedge anything.
fn download(stack: &mut Stack, host: &str) -> Result<usize, &'static str> {
    let result = run_download(stack, host);
    if result.is_err() {
        teardown(stack);
    }
    result
}

fn run_download(stack: &mut Stack, host: &str) -> Result<usize, &'static str> {
    let handle = stack.tcp5_handle;
    let gw = net::SLIRP_GATEWAY;
    let ip = Ipv4Address::new(gw[0], gw[1], gw[2], gw[3]);

    // (1) Request (static: `build_get` is small but the exchange
    // discipline in `ai.rs` keeps requests off the stack too).
    // SAFETY: single-use static (module note), written only here.
    let req = unsafe { &mut *addr_of_mut!(NET_REQ) };
    let req_len = http::build_get(req, host, PAYLOAD_PATH).ok_or("GET request does not fit")?;

    // (2) Connect — a leftover mid-handshake socket is aborted first;
    // TimeWait/Closed are what `connect` accepts (`ai.rs`'s documented
    // smoltcp observation), so the previous `ai` exchange's close is
    // no obstacle. Bounded retries: the responder is a respawnable
    // `nc` loop (rendezvous race), three refusals mean it is down.
    {
        let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
        if sock.is_open() {
            sock.abort();
        }
    }
    connect_payload(stack, handle, ip)?;

    // (3) Send the GET (bounded, poll-driven — `plain_get_smoke`'s
    // pattern; smoltcp owns retransmission).
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut sent = 0usize;
    while sent < req_len {
        stack.poll();
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&req[sent..])
        {
            Ok(n) => sent += n,
            Err(_) => return Err("tcp send rejected (connection lost)"),
        }
        if clock::now_ms() > deadline {
            return Err("tcp send timeout");
        }
    }

    // (4) Read + frame into [`DOWNLOAD`].
    let total = read_payload(stack, handle)?;

    // (5) Clean close: FIN → TimeWait/Closed (the `ai`/`tls` proof).
    stack.sockets.get_mut::<tcp::Socket>(handle).close();
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    loop {
        stack.poll();
        let state = stack.sockets.get::<tcp::Socket>(handle).state();
        if state == tcp::State::TimeWait || state == tcp::State::Closed {
            return Ok(total);
        }
        if clock::now_ms() > deadline {
            return Err("timeout closing connection (never reached TimeWait/Closed)");
        }
    }
}

/// Establish the payload connection with bounded retries — the
/// `ai::connect` pattern (SYN+RST lands in `Closed`; retry, but three
/// refusals mean the responder is down → fail closed).
fn connect_payload(
    stack: &mut Stack,
    handle: SocketHandle,
    ip: Ipv4Address,
) -> Result<(), &'static str> {
    let deadline = clock::now_ms() + OP_DEADLINE_MS;
    let mut attempts = 0u8;
    loop {
        {
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if let Err(e) = sock.connect(
                stack.iface.context(),
                (ip, PAYLOAD_PORT),
                PAYLOAD_HANDLE_LOCAL_PORT,
            ) {
                serial_println!("netinstall: connect rejected: {e:?}");
                return Err("tcp connect rejected");
            }
        }
        loop {
            stack.poll();
            match stack.sockets.get::<tcp::Socket>(handle).state() {
                tcp::State::Established => return Ok(()),
                tcp::State::Closed => break, // refused/RST → retry below
                _ => {}
            }
            if clock::now_ms() > deadline {
                return Err("tcp connect timeout");
            }
        }
        attempts += 1;
        if attempts >= 3 {
            return Err("connection refused by the payload server (nc loop down?)");
        }
        serial_println!("netinstall: connect refused, retrying ({attempts}/3)");
    }
}

/// Frame the payload response into [`DOWNLOAD`]: status 200 and a
/// `Content-Length` that exactly equals the received body, both
/// asserted fail-closed; the body may never exceed
/// [`DOWNLOAD_CAP`]. Returns the stored byte count.
fn read_payload(stack: &mut Stack, handle: SocketHandle) -> Result<usize, &'static str> {
    // SAFETY: single-use statics (module notes). Reset first: a
    // half-read previous response must never validate this one.
    // SAFETY: as above.
    let parser = unsafe { &mut *addr_of_mut!(NET_PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(NET_STAGING) };
    // SAFETY: as above; `n` is bounded by the contract below.
    let body = unsafe { &mut *addr_of_mut!(DOWNLOAD) };

    let mut stored = 0usize;
    let mut head_checked = false;
    // Input scratch on the stack (1460 B — the `ai.rs` split: `feed`
    // takes `input` and `body_out` as distinct buffers).
    let mut scratch = [0u8; NET_SCRATCH];
    let deadline = clock::now_ms() + NET_DEADLINE_MS;
    loop {
        stack.poll();
        let (can_recv, may_recv, queued, closed) = {
            let sock = stack.sockets.get::<tcp::Socket>(handle);
            (
                sock.can_recv(),
                sock.may_recv(),
                sock.recv_queue(),
                sock.state() == tcp::State::Closed,
            )
        };
        if can_recv {
            let n = stack
                .sockets
                .get_mut::<tcp::Socket>(handle)
                .recv_slice(&mut scratch)
                .unwrap_or(0);
            let progress = parser
                .feed(&scratch[..n], staging)
                .map_err(|_| "payload response refused")?;
            // Head assertions as soon as it parses (once per response).
            if !head_checked && let Some(status) = parser.status() {
                if status != 200 {
                    return Err("unexpected HTTP status (expected 200)");
                }
                if parser.content_length().is_none() {
                    return Err("payload response has no Content-Length");
                }
                head_checked = true;
            }
            if progress.body > 0 {
                // `progress.body ≤ staging` (feed never expands), so
                // this copy is in-bounds once the cap check passes —
                // a server pushing more than the bound fails here,
                // never truncates silently.
                if stored + progress.body > DOWNLOAD_CAP {
                    return Err("payload exceeds the byte bound");
                }
                body[stored..stored + progress.body].copy_from_slice(&staging[..progress.body]);
                stored += progress.body;
            }
            if progress.complete {
                break;
            }
            continue;
        }
        if (!may_recv && queued == 0) || closed {
            // Server FIN: completes a Content-Length-framed response
            // already done, fails a truncated one.
            parser.eof().map_err(|_| "truncated payload response")?;
            break;
        }
        if clock::now_ms() > deadline {
            return Err("timeout waiting for the payload");
        }
    }
    if !head_checked {
        return Err("payload response head never parsed");
    }
    let declared = parser
        .content_length()
        .ok_or("payload response has no Content-Length")?;
    if declared != stored as u64 {
        return Err("payload shorter than Content-Length");
    }
    Ok(stored)
}

/// Best-effort teardown of a failed download: abort (RST) so the next
/// connection finds `tcp5` connectable — TimeWait/Closed need nothing.
fn teardown(stack: &mut Stack) {
    let handle = stack.tcp5_handle;
    let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
    if sock.is_open() {
        sock.abort();
    }
}

// ---------------------------------------------------------------------------
// ustar walking (docs/installer.md §6.1)
// ---------------------------------------------------------------------------

/// Parse a POSIX **ustar** archive in place, filling `files` with
/// slices of `archive`. Bounded and validated per header (the values
/// below were pinned against real `bsdtar --format ustar` output, see
/// docs/installer.md §8.4):
///
/// - a full 512-byte header must be inside the buffer, an all-zero
///   block ends the archive (≥1 file required),
/// - the header checksum (6 octal digits + NUL + space at 148..156)
///   must match the byte sum with the field masked to spaces — both
///   the unsigned and the historical signed variant are accepted,
/// - magic `ustar\0` or `ustar ` (POSIX/GNU),
/// - type `0`/NUL = file (recorded), `5` = directory (skipped — the
///   payload is flat), anything else (pax/GNU extensions) refused,
/// - size is octal, its data range must fit inside the archive,
/// - the name is 1..=100 bytes of printable ASCII with no `/` and an
///   empty `prefix` field (v1 installs at the volume root only),
/// - at most [`MAX_PAYLOAD_FILES`] files.
///
/// Returns the file count.
fn parse_tar(
    archive: &'static [u8],
    files: &mut [PayloadFile<'static>],
) -> Result<usize, &'static str> {
    let mut offset = 0usize;
    let mut count = 0usize;
    loop {
        let Some(header) = archive.get(offset..offset + 512) else {
            // Ran out of buffer without a zero block: accept a clean
            // exact end once at least one file was seen (some tools
            // omit the trailing blocks), refuse everything else.
            if count == 0 {
                return Err("payload is not a ustar archive");
            }
            return Ok(count);
        };
        if header.iter().all(|&b| b == 0) {
            if count == 0 {
                return Err("payload is not a ustar archive");
            }
            return Ok(count);
        }

        // Checksum: sum with bytes 148..156 counted as spaces; accept
        // the unsigned sum or the historical signed variant.
        let declared = octal(&header[148..156]).map_err(|_| "bad header checksum field")?;
        let (mut unsigned, mut signed) = (0u64, 0i64);
        for (i, &byte) in header.iter().enumerate() {
            let byte = if (148..156).contains(&i) { b' ' } else { byte };
            unsigned = unsigned.wrapping_add(u64::from(byte));
            signed = signed.wrapping_add(i64::from(byte as i8));
        }
        if declared != unsigned && declared != signed as u64 {
            return Err("header checksum mismatch");
        }

        // Magic: POSIX `ustar\0` or GNU `ustar `.
        let magic = header.get(257..263).ok_or("truncated header")?;
        if magic != b"ustar\0" && magic != b"ustar " {
            return Err("not a ustar header");
        }

        let size = octal(&header[124..136]).map_err(|_| "bad size field")?;
        let typeflag = header[156];
        let data_start = offset + 512;
        let data_len = usize::try_from(size).map_err(|_| "entry size does not fit")?;
        let data_end = data_start
            .checked_add(data_len)
            .ok_or("entry data overflows the archive")?;
        if data_end > archive.len() {
            return Err("entry data runs past the end of the payload");
        }

        match typeflag {
            b'0' | 0 => {
                // Name: up to the first NUL in bytes 0..100.
                let field = header.get(0..100).ok_or("truncated header")?;
                let len = field.iter().position(|&b| b == 0).unwrap_or(100);
                if len == 0 {
                    return Err("file entry with an empty name");
                }
                let name_bytes = field.get(..len).ok_or("truncated name")?;
                if name_bytes
                    .iter()
                    .any(|&b| !(0x21..=0x7E).contains(&b) || b == b'/')
                {
                    return Err("payload file name is not printable ASCII without a path");
                }
                // `prefix` (345..500): non-empty means a path we do
                // not install — refuse instead of guessing.
                if header.get(345).is_some_and(|&b| b != 0) {
                    return Err("prefixed (subdirectory) payload names are unsupported");
                }
                let name = core::str::from_utf8(name_bytes).map_err(|_| "bad file name")?;
                let slot = files
                    .get_mut(count)
                    .ok_or("payload carries more files than the bound allows")?;
                // SAFETY: `name` and `data` borrow the `'static`
                // archive the caller passed (a slice of the DOWNLOAD
                // static) — they outlive every use here.
                *slot = PayloadFile {
                    name,
                    data: &archive[data_start..data_end],
                };
                count += 1;
            }
            b'5' => { /* directory entry: skipped (flat payload) */ }
            _ => return Err("unsupported payload entry type (pax/GNU extensions)"),
        }

        // Next header: data padded up to a 512-byte boundary.
        let padded = data_len.checked_add(511).ok_or("entry size overflows")? / 512 * 512;
        offset = data_start
            .checked_add(padded)
            .ok_or("archive offset overflows")?;
    }
}

/// Parse an octal field (up to 8 bytes: digits, then NUL/space
/// terminators; leading spaces allowed) with checked arithmetic —
/// overflow or a non-octal byte is refused, an all-terminator field
/// is refused (`seen_digit`).
fn octal(field: &[u8]) -> Result<u64, ()> {
    let mut value = 0u64;
    let mut seen_digit = false;
    for &byte in field {
        match byte {
            b'0'..=b'7' => {
                value = value.checked_mul(8).ok_or(())?;
                value = value.checked_add(u64::from(byte - b'0')).ok_or(())?;
                seen_digit = true;
            }
            b' ' | 0 => {
                if seen_digit {
                    break; // terminator after the digits
                }
                // leading padding — keep going
            }
            _ => return Err(()),
        }
    }
    if !seen_digit {
        return Err(());
    }
    Ok(value)
}

/// Fail-closed: name the refusal and stop the machine, so a broken
/// install can never look like a passing smoke.
fn fatal(e: impl core::fmt::Debug) -> ! {
    serial_println!("FATAL: install: {:?}", e);
    crate::halt()
}

/// Same, for preformatted messages (constants only — no disk data).
fn fatal_msg(msg: &str) -> ! {
    serial_println!("FATAL: install: {}", msg);
    crate::halt()
}

// ---------------------------------------------------------------------------
// I2b: the real HTTPS source (docs/installer.md §8.8)
// ---------------------------------------------------------------------------

/// Which GitHub endpoint the caller asked for: a raw payload download,
/// or release metadata whose `payload.tar` asset URL must be resolved
/// first. Both start on [`GITHUB_API_HOST`] (the only chain our single
/// pinned root verifies), and both end in the same bounded tar path.
#[derive(Debug, Clone, Copy)]
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
enum RealSource {
    Raw,
    ReleaseMetadata,
}

/// A validated, owned request target. Owned because a redirect chain
/// produces new hosts/paths while the previous `Url` is being dropped.
#[derive(Debug, Clone)]
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
struct Endpoint {
    /// Allowlisted hostname, also used as SNI and `Host` header.
    host: String,
    /// Absolute path plus optional query (no fragment, no credentials).
    target: String,
}

/// Hosts we may talk to on the real path. `api.github.com` terminates at
/// the pinned USERTrust ECC root (verified live); `github.com` is needed
/// only to *detect* the release-asset redirect and refuse it by name;
/// `objects.githubusercontent.com` is allowed for a future host whose
/// chain the pinned verifier accepts. Never an arbitrary `Location`.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn host_allowed(host: &str) -> bool {
    matches!(
        host,
        GITHUB_API_HOST | "github.com" | "objects.githubusercontent.com"
    )
}

/// Host check with a dedicated, actionable message for the one host a
/// GitHub release asset always redirects to. Its chain ends at ISRG Root
/// X1, which our single-anchor verifier refuses (docs §1.3/§6.2) —
/// a second root is a separate milestone, so we refuse *before* opening
/// a connection we know cannot authenticate.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn check_host(host: &str) -> Result<(), String> {
    if host_allowed(host) {
        return Ok(());
    }
    if host == "release-assets.githubusercontent.com" {
        return Err(String::from(
            "release assets redirect to release-assets.githubusercontent.com, \
             whose ISRG Root X1 chain the pinned verifier rejects — publish \
             payload.tar in the repo and use the contents endpoint",
        ));
    }
    Err(String::from("host is not on the HTTPS allowlist"))
}

/// Validate a `Url` and turn it into a request target. Every check is
/// fail-closed: https only, port 443 only, allowlisted host only, no
/// userinfo, no fragment, printable ASCII target within the static
/// request buffer.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn endpoint_of(url: &Url) -> Result<Endpoint, String> {
    if url.scheme() != "https" {
        return Err(String::from("only https is allowed for the real source"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(String::from("credentials in the payload URL are refused"));
    }
    if url.fragment().is_some() {
        return Err(String::from("URL fragments are refused"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| String::from("URL has no host"))?;
    check_host(host)?;
    if url.port_or_known_default() != Some(443) {
        return Err(String::from("only https port 443 is allowed"));
    }
    let mut target = String::from(url.path());
    if let Some(query) = url.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.is_empty()
        || target.len() > 512
        || !target.is_ascii()
        || target.bytes().any(|b| !(0x21..=0x7E).contains(&b))
    {
        return Err(String::from("request target is malformed or too long"));
    }
    Ok(Endpoint {
        host: String::from(host),
        target,
    })
}

/// Classify the caller's URL and reject anything outside the two
/// documented GitHub shapes. The `?ref=` on the contents URL is left in
/// the request target verbatim (validated by [`endpoint_of`]).
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn classify_source(url: &str) -> Result<(RealSource, Endpoint), String> {
    let parsed = Url::parse(url).map_err(|_| String::from("invalid payload URL"))?;
    if parsed.host_str() != Some(GITHUB_API_HOST) {
        return Err(String::from(
            "a real install must start on the GitHub API host",
        ));
    }
    let endpoint = endpoint_of(&parsed)?;
    let segments: alloc::vec::Vec<&str> = parsed
        .path_segments()
        .ok_or_else(|| String::from("payload URL has no path"))?
        .collect();
    if segments.len() != 5
        || segments[0] != "repos"
        || !valid_repo_part(segments[1])
        || !valid_repo_part(segments[2])
    {
        return Err(String::from(
            "expected /repos/<owner>/<repo>/contents/<file> or /releases/latest",
        ));
    }
    let source = match (segments[3], segments[4]) {
        ("contents", _) => RealSource::Raw,
        ("releases", "latest") => RealSource::ReleaseMetadata,
        _ => {
            return Err(String::from(
                "unsupported GitHub source path (contents or releases/latest only)",
            ));
        }
    };
    Ok((source, endpoint))
}

/// GitHub owner/repo path component: 1..=100 visible ASCII characters,
/// at least one alphanumeric (so `..` can never be a component).
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn valid_repo_part(part: &str) -> bool {
    !part.is_empty()
        && part.len() <= 100
        && part
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && part.bytes().any(|b| b.is_ascii_alphanumeric())
}

/// Socket/local-port pairs for the initial request and up to two
/// redirects. Each connection gets a fresh socket because smoltcp keeps
/// a closed TCP tuple in TIME-WAIT for ten seconds (the same reason the
/// boot chain owns one socket per exchange).
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn hop_for(stack: &Stack, hop: usize) -> Result<(SocketHandle, u16), String> {
    match hop {
        0 => Ok((stack.tcp7_handle, 49168)),
        1 => Ok((stack.tcp8_handle, 49169)),
        2 => Ok((stack.tcp9_handle, 49170)),
        _ => Err(String::from("HTTPS redirect cap exceeded")),
    }
}

/// One complete HTTPS exchange over an already-open `tls_open_soft`
/// connection: send the serialized GET, frame the response, store a
/// **200** body in `sink` (bounded by `cap`, never truncated), copy a
/// `Location` value for the caller's allowlist check, and close
/// best-effort. A non-200 body is counted but discarded — metadata
/// errors and redirect pages must never become a payload.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn tls_exchange(
    tls: TlsConnection<'_, TlsStream<'_>, Aes128GcmSha256>,
    request: &[u8],
    sink: &mut [u8],
    cap: usize,
) -> Result<(u16, usize, usize), &'static str> {
    let mut tls = tls;
    if tls.write_all(request).is_err() {
        return Err("TLS write failed");
    }
    if tls.flush().is_err() {
        return Err("TLS flush failed");
    }

    // SAFETY: single-use statics (module note). Reset first — one
    // parser serves every sequential exchange on this path.
    let parser = unsafe { &mut *addr_of_mut!(HTTPS_PARSER) };
    parser.reset();
    let staging = unsafe { &mut *addr_of_mut!(HTTPS_STAGING) };
    let loc = unsafe { &mut *addr_of_mut!(HTTPS_LOC) };
    let mut scratch = [0u8; NET_SCRATCH];
    let mut status = 0u16;
    let mut head = false;
    let mut stored = 0usize;
    let mut loc_len = 0usize;
    loop {
        match tls.read(&mut scratch) {
            Ok(0) => {
                if parser.eof().is_err() {
                    return Err("truncated HTTPS response");
                }
                break;
            }
            Ok(n) => {
                let progress = parser
                    .feed(&scratch[..n], staging)
                    .map_err(|_| "HTTPS response refused")?;
                if !head && let Some(s) = parser.status() {
                    head = true;
                    status = s; // parsed u16 — safe to log, never raw wire text
                    if let Some(value) = http::header_value(parser.head(), b"location") {
                        loc_len = loc.len().min(value.len());
                        loc[..loc_len].copy_from_slice(&value[..loc_len]);
                    }
                }
                if status == 200 && progress.body > 0 {
                    let Some(next) = stored.checked_add(progress.body) else {
                        return Err("response body exceeds the byte bound");
                    };
                    if next > cap || progress.body > sink.len().saturating_sub(stored) {
                        return Err("response body exceeds the byte bound");
                    }
                    sink[stored..next].copy_from_slice(&staging[..progress.body]);
                    stored = next;
                }
                if progress.complete {
                    break;
                }
            }
            Err(TlsError::ConnectionClosed) => {
                // Authenticated shutdown doubles as EOF: a framed body
                // ending here was truncated, never "close enough".
                if parser.eof().is_err() {
                    return Err("truncated HTTPS response");
                }
                break;
            }
            Err(_) => return Err("TLS read failed"),
        }
    }
    if !head {
        return Err("HTTPS response head never parsed");
    }
    // close_notify is best-effort; the next `tls_open_soft` aborts any
    // socket still open on this handle (no TIME-WAIT reuse hazard).
    let _ = tls.close();
    Ok((status, stored, loc_len))
}

/// GET `endpoint` over DNS → TLS 1.3 (pinned root) → HTTP, with at most
/// two redirects. Every hop is re-validated against the host allowlist
/// before DNS, and an https→http downgrade is refused. Returns the
/// final status and the number of body bytes stored in `sink`.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn https_get(
    stack: &mut Stack,
    start: Endpoint,
    headers: &[&str],
    sink: &mut [u8],
    cap: usize,
) -> Result<(u16, usize), String> {
    let mut endpoint = start;
    for hop in 0..MAX_HTTPS_HOPS {
        let ip = match stack.resolve(&endpoint.host) {
            Some(ip) => ip,
            None => return Err(String::from("DNS failed for the payload host")),
        };
        let (handle, port) = hop_for(stack, hop)?;
        // SAFETY: single-use static; the request is consumed before the
        // next hop rebuilds it.
        let req = unsafe { &mut *addr_of_mut!(HTTPS_REQ) };
        let req_len = http::build_request(req, &endpoint.host, &endpoint.target, headers)
            .ok_or_else(|| String::from("HTTPS request does not fit the buffer"))?;
        let (status, total, loc_len) = {
            let tls = tls::tls_open_soft(stack, handle, ip, &endpoint.host, port)?;
            // SAFETY: the mutable borrow above ended; immutable read of
            // the serialized request while the TLS exchange runs.
            let req = unsafe { &*addr_of!(HTTPS_REQ) };
            tls_exchange(tls, &req[..req_len], sink, cap).map_err(String::from)?
        };
        if status == 200 {
            return Ok((status, total));
        }
        if !(300..400).contains(&status) {
            return Err(String::from(
                "payload source returned an unexpected HTTP status",
            ));
        }
        if hop + 1 == MAX_HTTPS_HOPS {
            return Err(String::from("HTTPS redirect cap exceeded"));
        }
        if loc_len == 0 {
            return Err(String::from("redirect without a Location header"));
        }
        // SAFETY: single-use static, written by this exchange only.
        let raw = unsafe { &HTTPS_LOC[..loc_len] };
        // The release-asset host is rejected by name *before* URL
        // joining, even when its signed Location is longer than our
        // 512-byte cap (and would otherwise look merely malformed).
        if raw.starts_with(b"https://release-assets.githubusercontent.com/") {
            return Err(String::from(
                "release assets redirect to release-assets.githubusercontent.com, \
                 whose ISRG Root X1 chain the pinned verifier rejects — publish \
                 payload.tar in the repo and use the contents endpoint",
            ));
        }
        let reference = core::str::from_utf8(raw)
            .map_err(|_| String::from("redirect Location is not valid UTF-8"))?;
        let parsed = match Url::parse(reference) {
            Ok(url) => url,
            Err(_) => {
                // A relative Location needs an absolute base; build it
                // from the already-validated endpoint (no wire text).
                let base = alloc::format!("https://{}{}", endpoint.host, endpoint.target);
                let base =
                    Url::parse(&base).map_err(|_| String::from("malformed redirect base"))?;
                base.join(reference)
                    .map_err(|_| String::from("malformed redirect Location"))?
            }
        };
        endpoint = endpoint_of(&parsed)?;
    }
    Err(String::from("HTTPS redirect cap exceeded"))
}

/// Minimal, bounded JSON scanner for the one field we need from
/// `/releases/latest`: the `browser_download_url` of the asset named
/// `payload.tar`. Input is already capped by [`JSON_CAP`]; every string,
/// nesting level and number is checked, unknown fields are skipped
/// structurally (never with a substring search), and malformed/truncated
/// input is an `Err`. Unlike `aiwire`'s typed `serde_json` responses this
/// is a three-field reader, kept here because adding dependencies or
/// editing that crate is outside this milestone's surface.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
struct Json<'a> {
    bytes: &'a [u8],
    pos: usize,
}

// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
impl<'a> Json<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Json { bytes, pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn take(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, want: u8) -> Result<(), &'static str> {
        self.ws();
        if self.take() == Some(want) {
            Ok(())
        } else {
            Err("json: unexpected byte")
        }
    }

    /// Parse a JSON string into `out`, refusing any escape we would have
    /// to materialize as a non-ASCII code point (URLs and asset names on
    /// this API are plain ASCII). The returned `&str` borrows `out`.
    fn string_into<'b>(&mut self, out: &'b mut [u8]) -> Result<&'b str, &'static str> {
        self.ws();
        if self.take() != Some(b'"') {
            return Err("json: expected a string");
        }
        let mut n = 0usize;
        loop {
            let byte = self.take().ok_or("json: unterminated string")?;
            let decoded = match byte {
                b'"' => break,
                b'\\' => match self.take().ok_or("json: unterminated escape")? {
                    b'"' => b'"',
                    b'\\' => b'\\',
                    b'/' => b'/',
                    b'u' => {
                        for _ in 0..4 {
                            let hex = self.take().ok_or("json: short unicode escape")?;
                            if !hex.is_ascii_hexdigit() {
                                return Err("json: bad unicode escape");
                            }
                        }
                        return Err("json: unicode escapes are not accepted in read fields");
                    }
                    _ => return Err("json: unsupported escape"),
                },
                0..=0x1F => return Err("json: control byte in string"),
                other => other,
            };
            if n == out.len() {
                return Err("json: string too long");
            }
            out[n] = decoded;
            n += 1;
        }
        core::str::from_utf8(&out[..n]).map_err(|_| "json: string is not UTF-8")
    }

    /// Validate and step over a string whose value we do not need.
    fn skip_string(&mut self) -> Result<(), &'static str> {
        self.ws();
        if self.take() != Some(b'"') {
            return Err("json: expected a string");
        }
        loop {
            match self.take().ok_or("json: unterminated string")? {
                b'"' => return Ok(()),
                b'\\' => match self.take().ok_or("json: unterminated escape")? {
                    b'u' => {
                        for _ in 0..4 {
                            let hex = self.take().ok_or("json: short unicode escape")?;
                            if !hex.is_ascii_hexdigit() {
                                return Err("json: bad unicode escape");
                            }
                        }
                    }
                    b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {}
                    _ => return Err("json: unsupported escape"),
                },
                0..=0x1F => return Err("json: control byte in string"),
                _ => {}
            }
        }
    }

    fn keyword(&mut self, word: &[u8]) -> Result<(), &'static str> {
        for &want in word {
            if self.take() != Some(want) {
                return Err("json: bad literal");
            }
        }
        Ok(())
    }

    fn number(&mut self) -> Result<(), &'static str> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let first = self.take().ok_or("json: bad number")?;
        if !first.is_ascii_digit() {
            return Err("json: bad number");
        }
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !self.take().is_some_and(|b| b.is_ascii_digit()) {
                return Err("json: bad fraction");
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.take().is_some_and(|b| b.is_ascii_digit()) {
                return Err("json: bad exponent");
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if !matches!(
            self.peek(),
            None | Some(b' ' | b'\n' | b'\r' | b'\t' | b',' | b']' | b'}')
        ) {
            return Err("json: trailing number garbage");
        }
        Ok(())
    }

    /// Skip one arbitrary JSON value with a nesting cap — a hostile
    /// metadata body cannot grow the kernel stack or hide a second
    /// `assets` key behind an unparsed value.
    fn skip_value(&mut self, depth: u8) -> Result<(), &'static str> {
        if depth > JSON_DEPTH_CAP {
            return Err("json: nesting too deep");
        }
        self.ws();
        match self.peek().ok_or("json: truncated value")? {
            b'"' => self.skip_string(),
            b'{' => {
                self.pos += 1;
                loop {
                    self.ws();
                    if self.peek() == Some(b'}') {
                        let _ = self.take();
                        return Ok(());
                    }
                    self.skip_string()?;
                    self.expect(b':')?;
                    self.skip_value(depth + 1)?;
                    self.separator()?;
                }
            }
            b'[' => {
                self.pos += 1;
                loop {
                    self.ws();
                    if self.peek() == Some(b']') {
                        let _ = self.take();
                        return Ok(());
                    }
                    self.skip_value(depth + 1)?;
                    self.separator()?;
                }
            }
            b't' => self.keyword(b"true"),
            b'f' => self.keyword(b"false"),
            b'n' => self.keyword(b"null"),
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err("json: unexpected value"),
        }
    }

    /// Consume the `,` or closing bracket/brace after a member/element.
    /// A comma immediately followed by a closing delimiter is a trailing
    /// comma (invalid JSON) and is refused rather than skipped over.
    fn separator(&mut self) -> Result<(), &'static str> {
        self.ws();
        match self.take() {
            Some(b',') => {
                self.ws();
                if matches!(self.peek(), Some(b'}' | b']')) {
                    return Err("json: trailing comma");
                }
                Ok(())
            }
            Some(b'}') | Some(b']') => {
                self.pos -= 1; // let the enclosing loop consume it
                Ok(())
            }
            _ => Err("json: missing separator"),
        }
    }
}

/// Find the `browser_download_url` of the asset named
/// [`RELEASE_ASSET_NAME`] in a releases/latest JSON body. Only those two
/// string fields are materialized; everything else is skipped
/// structurally. The URL comes back as a bounded slice of the
/// single-use [`ASSET_URL`] static.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
fn release_asset_url(json: &'static [u8]) -> Result<&'static str, &'static str> {
    let mut j = Json::new(json);
    let mut key = [0u8; JSON_KEY_CAP];
    // Parse the *whole* document before handing back a URL: a malformed
    // tail must not be accepted just because the asset was earlier.
    let mut result: Option<&'static str> = None;
    j.expect(b'{')?;
    loop {
        j.ws();
        if j.peek() == Some(b'}') {
            let _ = j.take();
            break;
        }
        let field = j.string_into(&mut key)?;
        let is_assets = field == "assets";
        j.expect(b':')?;
        if is_assets {
            j.expect(b'[')?;
            loop {
                j.ws();
                if j.peek() == Some(b']') {
                    let _ = j.take();
                    break;
                }
                j.expect(b'{')?;
                let mut named = false;
                let mut url: Option<&'static str> = None;
                loop {
                    j.ws();
                    if j.peek() == Some(b'}') {
                        let _ = j.take();
                        break;
                    }
                    let asset_field = j.string_into(&mut key)?;
                    j.expect(b':')?;
                    match asset_field {
                        "name" => {
                            let mut name = [0u8; JSON_NAME_CAP];
                            named = j.string_into(&mut name)? == RELEASE_ASSET_NAME;
                        }
                        "browser_download_url" if url.is_none() && result.is_none() => {
                            // SAFETY: single-use static; one `&'static
                            // mut` per field, and a duplicate field is
                            // skipped instead of borrowing it twice.
                            let out: &'static mut [u8] = unsafe {
                                core::slice::from_raw_parts_mut(
                                    addr_of_mut!(ASSET_URL) as *mut u8,
                                    JSON_URL_CAP,
                                )
                            };
                            url = Some(j.string_into(out)?);
                        }
                        _ => j.skip_value(0)?,
                    }
                    j.separator()?;
                }
                if named && result.is_none() {
                    result = url;
                }
                // Next array element (or the closing `]`): never leave
                // the separating comma for `expect(b'{')` to trip on.
                j.separator()?;
            }
        } else {
            j.skip_value(0)?;
        }
        j.separator()?;
    }
    result.ok_or("no payload.tar asset in the release metadata")
}

/// Real-source network install (`docs/installer.md` §8.8). **Not** part
/// of any boot chain or smoke marker: the shell/hardware integrator
/// calls it explicitly with [`NETINSTALL_REAL_URL`] (or a
/// `releases/latest` URL). With no target it is silent; with a target it
/// pre-flights capacity + GRUB modules, then does *all* network, JSON
/// and tar validation **before** [`install_payload`] writes a single
/// sector. A failed/rate-limited/404 fetch therefore returns an `Err`
/// and the disk is untouched — the mock `netprove` remains the CI gate.
// Opt-in path: the shell/hardware integrator wires this in (docs §8.8).
#[allow(dead_code)]
pub(crate) fn netprove_https(
    stack: &mut Stack,
    target: Option<&ata::Disk>,
    payloads: &Payloads,
    url: &str,
) -> Result<(), String> {
    let Some(target) = target else {
        return Ok(());
    };
    check_size(target)?;
    if payloads.grub().is_none() {
        return Err(String::from(
            "no GRUB artifacts captured (boot the installer ISO, not the installed system)",
        ));
    }

    let (source, endpoint) = classify_source(url)?;
    let headers_json = [USER_AGENT, ACCEPT_JSON, API_VERSION];
    let headers_raw = [USER_AGENT, ACCEPT_RAW, API_VERSION];
    let mut endpoint = endpoint;

    if matches!(source, RealSource::ReleaseMetadata) {
        // SAFETY: single-use static, one exchange at a time.
        let json = unsafe { &mut *addr_of_mut!(JSON_BUF) };
        let (status, n) = https_get(stack, endpoint, &headers_json, json, JSON_CAP)?;
        if status != 200 {
            return Err(String::from("release metadata was not HTTP 200"));
        }
        if n == 0 {
            return Err(String::from("release metadata is empty"));
        }
        // SAFETY: `https_get` wrote exactly `n` bytes into this static.
        let body: &'static [u8] =
            unsafe { core::slice::from_raw_parts(addr_of!(JSON_BUF) as *const u8, n) };
        let asset_url = release_asset_url(body)?;
        let parsed = Url::parse(asset_url)
            .map_err(|_| String::from("browser_download_url is not a valid URL"))?;
        endpoint = endpoint_of(&parsed)?;
        serial_println!("netinstall: release asset URL passed the host allowlist");
    }

    // SAFETY: single-use static; reused from the mock path, which is
    // never active at the same time as this opt-in path.
    let download = unsafe { &mut *addr_of_mut!(DOWNLOAD) };
    let (status, n) = https_get(stack, endpoint, &headers_raw, download, DOWNLOAD_CAP)?;
    if status != 200 {
        return Err(String::from("payload download was not HTTP 200"));
    }
    serial_println!("netinstall: {n} bytes received over HTTPS");
    // SAFETY: `https_get` wrote exactly `n` bytes, `n <= DOWNLOAD_CAP`.
    let archive: &'static [u8] =
        unsafe { core::slice::from_raw_parts(addr_of!(DOWNLOAD) as *const u8, n) };
    let mut files = [PayloadFile {
        name: "",
        data: &[],
    }; MAX_PAYLOAD_FILES];
    let count = parse_tar(archive, &mut files)?;
    serial_println!("netinstall: payload carries {count} files");

    install_payload(target, &files[..count], payloads);
    Ok(())
}
