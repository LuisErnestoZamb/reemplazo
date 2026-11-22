//! Milestones **I1** (docs/installer.md §3.2, §4, §8.3) and **I2**
//! (§6, §8.4): the install-to-disk flow (`INST_OK`) and the network
//! installer (`NETINST_OK`).
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
//!    the source volume (the FS1 machinery) into a fixed
//!    [`PAYLOAD_CAP`]-sized buffer and written to p2.
//! 4. **Verify** — re-mount p2 from scratch (fresh `Part` + fresh
//!    `fat::Fat16`, no state from the write surviving) and read both
//!    files back byte-exact against the bytes read from the source.
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
//! path uses and reads every file back byte-exact → `NETINST_OK`.
//! The host then re-verifies `target.img` against the **built kernel
//! binary** (xtask's `verify_installed_image`).
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
//! ## What these milestones deliberately do *not* do (I1b / later)
//!
//! - **No GRUB boot code on the target** (`boot.img` → LBA0,
//!   `core.img` → p1): the artifacts live on the ISO
//!   (`/boot/grub/{boot,core}.img`) but the kernel has no ISO9660
//!   reader and no multiboot2-module payload path yet (docs milestone
//!   `MOD_OK`) — there is no honest way for the kernel to *have* the
//!   bytes in I1, so the installed disk is not yet bootable. Deferred
//!   to I1b with the payload-delivery milestone, never faked:
//!   `INST_OK`/`NETINST_OK` assert only what they actually do.
//! - No shell `disks`/`install`/`netinstall` builtins (boot-time
//!   proof chosen for I1/I2 — see docs/installer.md §8.3/§8.4), no
//!   HTTPS fetch (TLS against a local server is impossible — §7.2;
//!   the real `api.github.com` fetch is a later milestone), no AHCI.

use crate::ata;
use crate::clock;
use crate::fs::{AtaDisk, stamp};
use crate::netstack::{OP_DEADLINE_MS, Stack};
use core::ptr::addr_of_mut;
use gptwire::{Guid, Partition, TYPE_BASIC_DATA, TYPE_BIOS_GRUB};
use net::http::{self, ResponseParser};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;

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
/// emits is kernel (≈1.7 MB) + a README ≈ 1.71 MB, so 2 MiB leaves
/// headroom while keeping a hostile/truncating server from growing
/// the static. Refused, never truncated.
const DOWNLOAD_CAP: usize = 2 * 1024 * 1024;
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
struct GptDev<'a>(&'a ata::Drive);

impl gptwire::Device for GptDev<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors) * 512
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
    &'a ata::Drive,
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
fn p2_window(target: &ata::Drive, first_lba: u64, last_lba: u64) -> Part<'_> {
    let bytes = (last_lba - first_lba + 1) * 512;
    Part(target, first_lba * 512, bytes)
}

/// Validate the install target (shared by [`prove`] and [`netprove`]):
/// the marked second disk, big enough for the layout. `None`
/// (silently — the caller returns without a word) when there is no
/// marked target; `FATAL:` + halt when one exists but is too small to
/// install onto. The probing itself happens **once in `kernel_main`**
/// (before the offline install rewrites LBA0 and erases the marker) —
/// this function only checks and reports.
fn prepare_target(target: Option<&ata::Drive>) -> Option<&ata::Drive> {
    let target = target?;
    let total = u64::from(target.sectors);
    if total < MIN_TARGET_SECTORS {
        serial_println!(
            "FATAL: install: target too small ({total} sectors, need {MIN_TARGET_SECTORS})"
        );
        crate::halt();
    }
    let mut name_buf = [0u8; 40];
    let model = target.model_name(&mut name_buf);
    serial_println!(
        "install: target '{model}' {total} sectors ({} MiB)",
        total / 2048
    );
    Some(target)
}

/// The shared install: GPT → format p2 → copy `files` → byte-exact
/// re-read (see the module docs). Any failure with a target present
/// is `FATAL: install:` + halt — both markers stand on this one path,
/// so `INST_OK` and `NETINST_OK` assert identical disk work.
fn install_payload(target: &ata::Drive, files: &[PayloadFile<'_>]) {
    // --- Step 1: GPT (docs/installer.md §3.2) ---
    let total = u64::from(target.sectors);
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
}

/// Length of the [`VERIFY`] scratch, checked against every payload
/// file before the read-back (a file bigger than the scratch is a
/// `FATAL`, never a truncated "pass").
const VERIFY_LEN: usize = DOWNLOAD_CAP;

/// Offline install (I1): read the payload from the source volume,
/// run [`install_payload`], print `INST_OK`. Silent without a marked
/// target disk; `FATAL:` + `halt()` on any failure with one.
pub(crate) fn prove(source: &ata::Drive, target: Option<&ata::Drive>) {
    let Some(target) = prepare_target(target) else {
        return; // no (marked) target disk → zero output, boot continues
    };

    // Read the payload from the source volume — the FS1 machinery,
    // bounded by [`PAYLOAD_CAP`] per file (a bigger file on the
    // source is refused, never truncated).
    let src_disk = AtaDisk(source);
    let src_fs = match fat::Fat16::mount(&src_disk) {
        Ok(fs) => fs,
        Err(e) => fatal(e),
    };
    let mut first = [0u8; PAYLOAD_CAP];
    let mut second = [0u8; PAYLOAD_CAP];
    let n_first = match read_named(&src_fs, PAYLOAD[0], &mut first) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    let n_second = match read_named(&src_fs, PAYLOAD[1], &mut second) {
        Ok(n) => n,
        Err(e) => fatal(e),
    };
    let files = [
        PayloadFile {
            name: PAYLOAD[0],
            data: &first[..n_first],
        },
        PayloadFile {
            name: PAYLOAD[1],
            data: &second[..n_second],
        },
    ];

    install_payload(target, &files);
    serial_println!("INST_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// Read `name` (bare, [`qualify`]-prefixed) from a mounted volume
/// into `buf` — the offline path's bounded source read.
fn read_named(
    fs: &fat::Fat16<'_, AtaDisk<'_>>,
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
pub(crate) fn netprove(stack: &mut Stack, target: Option<&ata::Drive>) {
    let Some(target) = prepare_target(target) else {
        return; // no marked target → no network noise either
    };

    let gw = net::SLIRP_GATEWAY;
    let host = alloc::format!("{}.{}.{}.{}", gw[0], gw[1], gw[2], gw[3]);
    serial_println!("netinstall: GET {host}:{PAYLOAD_PORT}{PAYLOAD_PATH}");
    let n = match download(stack, &host) {
        Ok(n) => n,
        Err(e) => fatal_msg(e),
    };
    serial_println!("netinstall: {n} bytes received");

    // SAFETY: `download` wrote exactly `n` bytes into the single-use
    // static (module note); `n ≤ DOWNLOAD_CAP` is its contract.
    let archive: &'static [u8] =
        unsafe { core::slice::from_raw_parts(core::ptr::addr_of!(DOWNLOAD) as *const u8, n) };
    let mut files = [PayloadFile {
        name: "",
        data: &[],
    }; MAX_PAYLOAD_FILES];
    let count = match parse_tar(archive, &mut files) {
        Ok(count) => count,
        Err(e) => fatal_msg(e),
    };
    serial_println!("netinstall: payload carries {count} files");

    install_payload(target, &files[..count]);
    serial_println!("NETINST_OK"); // machine-checked by `cargo xtask smoke-install`
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
