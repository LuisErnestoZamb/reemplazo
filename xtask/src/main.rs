//! xtask: build, package, and run the OS.
//!
//! Usage (from repo root): `cargo xtask <command>`
//!   check   fmt --check + clippy + host tests + kernel cross-build
//!   build   cross-compile the kernel (x86_64-unknown-none, release)
//!   user    cross-compile user-hello and copy it to boot/hello.elf
//!   iso     package target image as bootable ISO (GRUB i386-pc)
//!   smoke   boot the ISO headless; assert serial markers in order,
//!           then type a command through QEMU's monitor (KEYBOARD_OK)
//!   smoke-install  boot with a FAT16 source disk + a blank target disk;
//!           assert BLK_OK + FAT_OK + FS_WRITE_OK + FS_TREE_OK + INST_OK
//!           + GIT_CHECKOUT_OK + GIT_STORE_OK + GIT_PUSH_OK + NETINST_OK,
//!           verify the pushed pack on the host (git-pack + real git),
//!           then re-verify target.img on the host
//!   smoke-ssh  boot TWO VMs in one container: the first runs the sshd
//!           from its disk, the second authenticates and execs through
//!           QEMU's hostfwd (SSHD_OK + SSHD_EXEC_OK)
//!   run     build + iso + boot interactively (serial on stdio; keys
//!           can also be injected via the printed monitor address)
//!
//! Backends: grub-mkrescue always runs in the `reemplazo-tools` container
//! (no native macOS build). QEMU prefers a host `qemu-system-x86_64` and
//! falls back to the same container (Homebrew can't build QEMU on macOS 13).

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio, exit};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Containerized grub-mkrescue + qemu-system-x86_64 (tools/Dockerfile).
const TOOLS_IMAGE: &str = "reemplazo-tools";
/// Boot-phase budget: every serial marker up to `SHELL_OK` must appear
/// within this. The keyboard phase afterwards has its own deadline
/// Boot-phase budget for `smoke-install`: everything the plain smoke
/// does **plus** the two-disk work (full depth-1 git checkout of ~114
/// files onto FAT16, the I1 install, and the I2 network install
/// writing a ~2 MiB kernel through single-sector PIO — the
/// multi-sector DRQ handshake is deliberately never assumed). 30 s
/// proved too tight the day the kernel crossed 2 MiB; 60 s keeps the
/// failure mode honest (the guest is still *working*, not hung — every
/// poll/socket wait has its own bound).
const INSTALL_TIMEOUT: Duration = Duration::from_secs(60);
/// ([`KEYBOARD_PHASE_TIMEOUT`]) because it starts only once the shell
/// is up.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for connecting to QEMU's monitor, typing `echo KEYBOARD_OK`
/// with `sendkey`, and waiting for the shell's output. QEMU paces its
/// input queue at ~10 ms per press/delay/release (≈1 s for the
/// 17-key sequence), so this is generous headroom for a phase that
/// should take about a second.
const KEYBOARD_PHASE_TIMEOUT: Duration = Duration::from_secs(15);
/// Budget for the I1b **disk-boot phase**: boot `target.img` alone (no
/// ISO), GRUB from disk, then the installed kernel's whole boot chain
/// up to `SHELL_OK` — the network phases (DNS/git fetch/TLS/SSH) are
/// the slow part and dominate, exactly as in the ISO smoke's 30 s. 45 s
/// is that budget plus the slower CD-less disk read and margin; the
/// failure mode stays loud (the marker dump) rather than a silent hang.
const DISK_BOOT_TIMEOUT: Duration = Duration::from_secs(45);
/// Markers asserted from the target-boot serial. Chosen to prove the
/// **whole chain is really running from the installed disk**, not just
/// that GRUB printed something:
///
/// - `BOOT_OK` — GRUB (from LBA0/core.img on the target) handed over a
///   valid multiboot2 MBI to the kernel loaded from p2's `/KERNEL.ELF`;
/// - `VGA_OK` — the text mirror works in that handoff;
/// - `MEM_OK` / `ALLOC_OK` — the frame allocator and kernel heap came
///   up from the same MBI (no ISO, no source disk);
/// - `RTC_OK` — port I/O after interrupts;
/// - `PCI_OK` — the machine scan;
/// - `E1000_OK` — the NIC the chain needs (this is the marker missing
///   if the disk-boot QEMU's device set ever drifts);
/// - `SHELL_OK` — the kernel reached its idle shell *after* the full
///   fail-closed boot chain (DHCP/DNS/TLS/git/SSH, TUI/editor/AI/
///   browser). The markers not listed (`NET_OK`… `BROWSER_NAV_OK`) are
///   still asserted implicitly: `SHELL_OK` cannot print unless every
///   earlier phase passed (each one halts on failure), and the dump on
///   failure shows exactly where it stopped.
///
/// Not asserted: `USB_KBD_OK` (present, but the keyboard proof belongs
/// to `smoke`'s sendkey phase) and every disk marker (`BLK_OK`, `FAT_OK`,
/// `INST_OK`, …): the installed LBA0 is GRUB `boot.img`, so
/// `ata::probe` correctly finds no installer source magic and the
/// installer stays silent — the neutrality rule, observed here from the
/// other side.
const DISK_BOOT_MARKERS: [&str; 8] = [
    "BOOT_OK", "VGA_OK", "MEM_OK", "ALLOC_OK", "RTC_OK", "PCI_OK", "E1000_OK", "SHELL_OK",
];

/// Hash of the checkout path — the stable per-checkout discriminator.
/// `DefaultHasher::new()` uses fixed keys, so the same directory always
/// maps to the same value; parallel git worktrees (one per milestone)
/// therefore never collide.
fn checkout_hash(root: &Path) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    hasher.finish()
}

/// Container name unique to this checkout: `rm_container` works by
/// name, so parallel git worktrees must not force-remove each other's
/// VMs.
fn vm_container(root: &Path, kind: &str) -> String {
    format!("reemplazo-{kind}-{:016x}", checkout_hash(root))
}

/// Host TCP port for QEMU's HMP monitor, unique per checkout (same
/// hash as [`vm_container`]) and inside the dynamic/private range so
/// it does not tread on well-known services. The same value is
/// published by Docker (`-p 127.0.0.1:PORT:PORT`) and used by
/// [`type_echo_command`] to connect.
fn monitor_port(root: &Path) -> u16 {
    monitor_port_n(root, 0)
}

/// The same port with an offset — the two-VM harness gives each QEMU
/// its own monitor (only the client VM's is published to the host).
fn monitor_port_n(root: &Path, n: u64) -> u16 {
    49152 + ((checkout_hash(root).wrapping_add(n)) % 16384) as u16
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let root = repo_root();
    if cmd == "chat-mock" {
        // Internal subcommand: the host-backend mock server (spawned
        // by qemu_invocation, see spawn_chat_mock). Never fails the
        // caller's argument check.
        serve_chat_mock(&root);
        return;
    }
    let ok = match cmd.as_str() {
        "check" => check(&root),
        "build" => build_kernel(&root),
        "user" => build_user(&root),
        "smoke-user" => smoke_user(&root),
        "iso" => iso(&root),
        "smoke" => smoke(&root),
        "smoke-install" => smoke_install(&root),
        "smoke-ssh" => smoke_ssh(&root),
        "smoke-netinstall-real" => smoke_netinstall_real(&root),
        "run" => run(&root),
        "hwtest" => hwtest(&root),
        _ => {
            eprintln!(
                "usage: cargo xtask <check|build|user|iso|smoke|smoke-user|smoke-install|smoke-ssh|smoke-netinstall-real|run|hwtest>"
            );
            false
        }
    };
    if !ok {
        exit(1);
    }
}

fn repo_root() -> PathBuf {
    // xtask lives at <root>/xtask/src/main.rs.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live one level below the repo root")
        .to_path_buf()
}

fn sh(root: &Path, program: &str, args: &[&str]) -> bool {
    let status = Command::new(program).args(args).current_dir(root).status();
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("xtask: `{program} {}` failed with {s}", args.join(" "));
            false
        }
        Err(e) => {
            eprintln!("xtask: failed to run `{program}`: {e}");
            false
        }
    }
}

fn check(root: &Path) -> bool {
    // Host crates (xtask, mbi, net, …) and kernel are linted separately: the
    // kernel is no_std and only valid for x86_64-unknown-none, never host.
    sh(root, "cargo", &["fmt", "--all", "--check"])
        && sh(
            root,
            "cargo",
            &[
                "clippy",
                "-p",
                "xtask",
                "-p",
                "ahci-wire",
                "-p",
                "aiwire",
                "-p",
                "git-pktline",
                "-p",
                "ssh-wire",
                "-p",
                "editorbuf",
                "-p",
                "usbwire",
                "-p",
                "sky2-wire",
                "-p",
                "mbi",
                "-p",
                "html",
                "-p",
                "dom",
                "-p",
                "csscore",
                "-p",
                "net",
                "-p",
                "pci",
                "-p",
                "rtc",
                "-p",
                "fat",
                "-p",
                "git-pack",
                "-p",
                "gptwire",
                "-p",
                "git-store",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ],
        )
        && sh(
            root,
            "cargo",
            &[
                "clippy",
                "-p",
                "kernel",
                "--release",
                "--target",
                "x86_64-unknown-none",
                "--",
                "-D",
                "warnings",
            ],
        )
        && sh(
            root,
            "cargo",
            &[
                "clippy",
                "-p",
                "user-hello",
                "--release",
                "--target",
                "x86_64-unknown-none",
                "--",
                "-D",
                "warnings",
            ],
        )
        && sh(
            root,
            "cargo",
            &[
                "test",
                "-p",
                "xtask",
                "-p",
                "ahci-wire",
                "-p",
                "aiwire",
                "-p",
                "git-pktline",
                "-p",
                "ssh-wire",
                "-p",
                "editorbuf",
                "-p",
                "usbwire",
                "-p",
                "sky2-wire",
                "-p",
                "html",
                "-p",
                "dom",
                "-p",
                "csscore",
                "-p",
                "mbi",
                "-p",
                "net",
                "-p",
                "pci",
                "-p",
                "rtc",
                "-p",
                "fat",
                "-p",
                "git-pack",
                "-p",
                "gptwire",
                "-p",
                "git-store",
            ],
        )
        && build_kernel(root)
}

fn build_kernel(root: &Path) -> bool {
    sh(
        root,
        "cargo",
        &[
            "build",
            "-p",
            "kernel",
            "--release",
            "--target",
            "x86_64-unknown-none",
        ],
    )
}

/// Cross-compile the first userland ELF and stage it at
/// `target/iso-root/boot/hello.elf`. The integrator adds the
/// `module2 /boot/hello.elf hello` line to the **new smoke-user** GRUB
/// config; this command deliberately does not touch the existing
/// `iso()`/`smoke*` paths, so their ISOs stay byte-identical.
fn build_user(root: &Path) -> bool {
    // The user ELF is linked at USER_BASE = 0x8000_0000_0000 (512 GiB),
    // outside the small code model's signed-32-bit absolute relocation
    // range. `code-model=large` is scoped to THIS cargo invocation via
    // RUSTFLAGS — setting it in the global .cargo/config.toml changed the
    // kernel's codegen (2.4 -> 3.6 MiB) and broke boot. Keep the two
    // targets strictly separate.
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "user-hello",
            "--release",
            "--target",
            "x86_64-unknown-none",
        ])
        .env(
            "RUSTFLAGS",
            "-C target-cpu=x86-64 -C relocation-model=static -C code-model=large",
        )
        .current_dir(root)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("xtask user: cargo build failed with {s}");
            return false;
        }
        Err(e) => {
            eprintln!("xtask user: cannot run cargo: {e}");
            return false;
        }
    }
    let elf = root.join("target/x86_64-unknown-none/release/user-hello");
    let boot = root.join("target/iso-root/boot");
    if let Err(e) = std::fs::create_dir_all(&boot) {
        eprintln!("xtask user: cannot create {}: {e}", boot.display());
        return false;
    }
    let dest = boot.join("hello.elf");
    if let Err(e) = std::fs::copy(&elf, &dest) {
        eprintln!(
            "xtask user: cannot copy {} → {}: {e}",
            elf.display(),
            dest.display()
        );
        return false;
    }
    println!("xtask user: {} → {}", elf.display(), dest.display());
    true
}

/// Hito 6: cross-compile `user-git` (its own tiny workspace, so the root
/// member list stays owned by the integrator) and leave the ELF at
/// `target/x86_64-unknown-none/release/user-git`. `stage_git_module`
/// then copies it into the ISO under the multiboot module name `hello`,
/// which is the one name the kernel's U1 loader captures today. The git
/// ELF carries the hito-3 console + hito-4 FS/editor proofs plus the new
/// Spawn/Waitpid/IPC proof, so the whole marker chain stays intact.
/// Same `code-model=large` scoping rule as `build_user` — never set it globally.
fn build_user_git(root: &Path) -> bool {
    let manifest = root.join("user/git/Cargo.toml");
    let status = Command::new("cargo")
        .args([
            "build",
            "--manifest-path",
            &manifest.to_string_lossy(),
            "--release",
            "--target",
            "x86_64-unknown-none",
        ])
        .env(
            "RUSTFLAGS",
            "-C target-cpu=x86-64 -C relocation-model=static -C code-model=large",
        )
        .env("CARGO_TARGET_DIR", root.join("target"))
        .current_dir(root)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => {
            eprintln!("xtask user-git: cargo build failed with {s}");
            return false;
        }
        Err(e) => {
            eprintln!("xtask user-git: cannot run cargo: {e}");
            return false;
        }
    }
    let elf = root.join("target/x86_64-unknown-none/release/user-git");
    if !elf.is_file() {
        eprintln!("xtask user-git: no ELF at {}", elf.display());
        return false;
    }
    println!("xtask user-git: built {}", elf.display());
    true
}

/// Hito 6 counterpart of [`stage_hello_module`]: stage the `user-git`
/// ELF as the `hello` multiboot module for the dedicated `smoke-user` ISO.
/// Reuses the existing capture path in `kernel/src/userland/module.rs`, so
/// no kernel loader change is needed to run the Spawn/Waitpid/IPC process.
fn stage_git_module(root: &Path, iso_root: &Path, cfg_path: &Path) {
    let relative = root.join("target/x86_64-unknown-none/release/user-git");
    let bytes = match std::fs::read(&relative) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask user-git: cannot read {}: {e}", relative.display());
            return;
        }
    };
    if bytes.len() as u64 > HELLO_MODULE_CAP {
        eprintln!(
            "xtask user-git: ELF is {} B, above the {HELLO_MODULE_CAP} B module cap",
            bytes.len()
        );
        return;
    }
    if let Err(e) = std::fs::write(iso_root.join("boot/hello.elf"), bytes) {
        eprintln!("xtask user-git: cannot write boot/hello.elf: {e}");
        return;
    }
    let cfg = match std::fs::read_to_string(cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("xtask user-git: cannot read {}: {e}", cfg_path.display());
            return;
        }
    };
    if cfg.contains("module2 /boot/hello.elf hello") {
        return;
    }
    let cfg = cfg.replacen(
        "    boot\n",
        "    module2 /boot/hello.elf hello\n    boot\n",
        1,
    );
    if let Err(e) = std::fs::write(cfg_path, cfg) {
        eprintln!("xtask user-git: cannot write {}: {e}", cfg_path.display());
    }
}

/// The early config embedded **inside `core.img`** (`grub-mkimage -c`)
/// — this is what boots the *installed* disk (§4, §8.6):
///
/// - `search --no-floppy --file /KERNEL.ELF --set=root` finds the FAT16
///   partition by content, so the installed system does not depend on
///   the BIOS/GRUB drive number or on `(hd0,gpt2)` being the right one
///   (the `-p` prefix baked below still sets that as the fallback root
///   in `grub_set_prefix_and_root`, so even a failed search leaves a
///   working root on a single-disk machine);
/// - `multiboot2 /KERNEL.ELF` loads the kernel the installer wrote;
/// - `boot` transfers control (the `boot` command is a dependency of
///   `multiboot2.mod` in GRUB's `moddep.lst`, so it is in core).
///
/// The config runs from `grub_main` *after* the embedded modules are
/// loaded and after `root`/`prefix` are set (GRUB 2.12
/// `grub-core/kern/main.c`), which is why these commands exist.
const GRUB_EARLY_CFG: &str = "\
search --no-floppy --file /KERNEL.ELF --set=root
multiboot2 /KERNEL.ELF
boot
";

/// Build the I1b artifacts in the tools image, the exact commands
/// `grub-install` would use to obtain them (docs/installer.md §8.6):
///
/// - `grub-mkimage -O i386-pc` builds `core.img` for the BIOS platform
///   with the boot-critical modules only (`biosdisk` to read the disk,
///   `part_gpt` + `fat` to find p2, `multiboot2` to load our kernel,
///   `normal` for the command machinery, `search` + `search_fs_file`
///   for the embedded config), prefix `(hd0,gpt2)/boot/grub` (the
///   single-disk default the early config's `search` self-heals), and
///   the early config embedded;
/// - `boot.img` is copied verbatim from `grub-pc-bin`
///   (`/usr/lib/grub/i386-pc/boot.img`, 512 B); the *installer* patches
///   its LBA field and partition table later (§8.6) — the artifact on
///   the ISO is the pristine one;
/// - both are concatenated as `grubpayload.bin` = `boot.img ‖ core.img`
///   (the documented module layout; the kernel splits at 512 B). The
///   1 MiB check is the `bios_grub` bound: a `core.img` that no longer
///   fits p1 must fail the ISO build, not the install.
const GRUB_ARTIFACTS_SH: &str = "\
set -e
grub-mkimage -O i386-pc -o /work/boot/core.img \
    -p '(hd0,gpt2)/boot/grub' -c /work/boot/early.cfg \
    biosdisk part_gpt fat multiboot2 normal search search_fs_file
cp /usr/lib/grub/i386-pc/boot.img /work/boot/boot.img
core=$(wc -c < /work/boot/core.img)
[ \"$core\" -le 1048576 ]
cat /work/boot/boot.img /work/boot/core.img > /work/boot/grubpayload.bin
ls -l /work/boot/boot.img /work/boot/core.img /work/boot/grubpayload.bin
";

fn iso(root: &Path) -> bool {
    iso_inner(root, false, false)
}

/// Hard cap on the `hello` module: the kernel's capture buffer is 4 MiB
/// (`kernel/src/userland/module.rs::HELLO_MODULE_CAP`). Keep both in sync.
const HELLO_MODULE_CAP: u64 = 4 * 1024 * 1024;

/// Where the userland agent's build puts the first user ELF. The first hit
/// wins; `target/iso-root/hello.elf` lets a caller pre-stage the binary
/// without owning `user/hello/`.
// Retained for `xtask user` / the integrator: hito 3's smoke-user stages
// the shell instead, but the U1 hello path is still a supported build.
#[allow(dead_code)]
const HELLO_SOURCES: &[&str] = &[
    // The real cargo artifact (built by `xtask user` / `iso_inner`).
    "target/x86_64-unknown-none/release/user-hello",
    "user/hello/target/x86_64-unknown-none/release/hello",
    "user/hello/target/x86_64-unknown-none/release/hello.elf",
    "user/hello/hello.elf",
    "target/iso-root/boot/hello.elf",
    "target/iso-root/hello.elf",
];

/// First existing path for the userland `hello` build, if any.
#[allow(dead_code)]
fn hello_source(root: &Path) -> Option<std::path::PathBuf> {
    HELLO_SOURCES
        .iter()
        .map(|src| root.join(src))
        .find(|path| path.is_file())
}

/// Copy the `hello` ELF into the ISO and add `module2 /boot/hello.elf hello`
/// to GRUB's config (the name is the module's command line, matched by the
/// kernel before its frame allocator exists). Missing binary → silent
/// no-op; present but too large → loud ISO-build failure.
#[allow(dead_code)]
fn stage_hello_module(root: &Path, iso_root: &Path, cfg_path: &Path) {
    let Some(relative) = hello_source(root) else {
        eprintln!("xtask: no user hello ELF found; skipping ELF_OK module");
        return;
    };
    let bytes = match std::fs::read(&relative) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask: cannot read {}: {e}", relative.display());
            return;
        }
    };
    if bytes.len() as u64 > HELLO_MODULE_CAP {
        eprintln!(
            "xtask: user hello ELF is {} B, above the {HELLO_MODULE_CAP} B module cap",
            bytes.len()
        );
        return;
    }
    if let Err(e) = std::fs::write(iso_root.join("boot/hello.elf"), bytes) {
        eprintln!("xtask: cannot write boot/hello.elf: {e}");
        return;
    }
    let cfg = match std::fs::read_to_string(cfg_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("xtask: cannot read {}: {e}", cfg_path.display());
            return;
        }
    };
    if cfg.contains("module2 /boot/hello.elf hello") {
        return;
    }
    let cfg = cfg.replacen(
        "    boot\n",
        "    module2 /boot/hello.elf hello\n    boot\n",
        1,
    );
    if let Err(e) = std::fs::write(cfg_path, cfg) {
        eprintln!("xtask: cannot write {}: {e}", cfg_path.display());
    }
}

/// [`iso`] with the hardware bring-up module: when `hwtest` is set,
/// the ISO carries `boot/sshd.bin` (one keypair: host seed ‖ the
/// authorized client's raw public key) and the GRUB config loads it
/// as the multiboot2 module `sshd`, which switches the kernel into
/// `crate::hwtest` (static address, sshd, no smoke chain).
fn iso_inner(root: &Path, hwtest: bool, user_mode: bool) -> bool {
    if !build_kernel(root) {
        return false;
    }
    // U1: build/stage the userland ELF only in the dedicated smoke-user
    // ISO. The standard smoke/install/ssh/hwtest ISOs stay byte-identical
    // (no hello module -> no ELF_OK -> original marker chains).
    // Hito 6: the smoke-user ISO runs the user-git process under the existing
    // `hello` module name (the U1 loader's one capture slot). It carries the
    // hito-3 console and hito-4 FS/editor proofs plus the Spawn/IPC proof, so
    // the whole marker chain stays in order.
    if user_mode && !build_user_git(root) {
        return false;
    }
    let kernel = root.join("target/x86_64-unknown-none/release/kernel");
    let iso_root = root.join("target/iso-root");
    let _ = std::fs::remove_dir_all(&iso_root);
    let boot_dir = iso_root.join("boot/grub");
    if let Err(e) = std::fs::create_dir_all(&boot_dir) {
        eprintln!("xtask: cannot create {}: {e}", boot_dir.display());
        return false;
    }
    if let Err(e) = std::fs::copy(&kernel, iso_root.join("boot/kernel.elf")) {
        eprintln!("xtask: cannot copy {}: {e}", kernel.display());
        return false;
    }
    if let Err(e) = std::fs::copy(
        root.join("iso/boot/grub/grub.cfg"),
        boot_dir.join("grub.cfg"),
    ) {
        eprintln!("xtask: cannot copy grub.cfg: {e}");
        return false;
    }

    if hwtest {
        // Keys + module: one keypair serves as the host key and the
        // authorized client key (self-signed bring-up setup).
        let mut client_seed = [0u8; 32];
        let mut server_seed = [0u8; 32];
        let mut authorized = Vec::new();
        if let Err(e) = generate_ssh_smoke_keys(
            &iso_root,
            &mut client_seed,
            &mut server_seed,
            &mut authorized,
        ) {
            eprintln!("xtask hwtest: cannot write the sshd keys: {e}");
            return false;
        }
        let key_file = iso_root.join(INTEROP_KEY_FILE);
        let raw_key = match std::fs::read(&key_file) {
            Ok(raw) => raw,
            Err(e) => {
                eprintln!("xtask hwtest: cannot read {}: {e}", key_file.display());
                return false;
            }
        };
        let (seed, public) = match parse_openssh_ed25519(&raw_key) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("xtask hwtest: cannot parse {}: {e}", key_file.display());
                return false;
            }
        };
        let mut module = [0u8; 64];
        module[..32].copy_from_slice(&seed);
        module[32..].copy_from_slice(&public);
        let module_path = iso_root.join("boot/sshd.bin");
        if let Err(e) = std::fs::write(&module_path, module) {
            eprintln!("xtask hwtest: cannot write {}: {e}", module_path.display());
            return false;
        }
        // Load it as the multiboot2 module `sshd` (the kernel matches
        // the command line, not the file name).
        let cfg_path = boot_dir.join("grub.cfg");
        let cfg = match std::fs::read_to_string(&cfg_path) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!("xtask hwtest: cannot read {}: {e}", cfg_path.display());
                return false;
            }
        };
        let cfg = cfg.replacen(
            "    boot\n",
            "    module2 /boot/sshd.bin sshd\n    boot\n",
            1,
        );
        if let Err(e) = std::fs::write(&cfg_path, cfg) {
            eprintln!("xtask hwtest: cannot write {}: {e}", cfg_path.display());
            return false;
        }
    }
    // U1: stage the first userland ELF as multiboot2 module `hello`.
    // `m-userland-elf` owns `user/hello/`; until that binary lands this is
    // a silent no-op, so diskless/installed-system boots keep their marker
    // chains. With the ELF present the kernel's ELF_OK proof runs after
    // SHELL_OK (the module is captured before `memory::init`).
    if user_mode {
        stage_git_module(root, &iso_root, &boot_dir.join("grub.cfg"));
    }
    // I1b: the config embedded in the installed disk's core.img.
    if let Err(e) = std::fs::write(iso_root.join("boot/early.cfg"), GRUB_EARLY_CFG) {
        eprintln!("xtask: cannot write early.cfg: {e}");
        return false;
    }
    // Image tag is cheap to rebuild; Docker layer cache makes re-runs fast.
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return false;
    }
    // I1b: GRUB's boot.img + core.img, concatenated as the `grubpayload`
    // multiboot2 module (see GRUB_ARTIFACTS_SH). Runs before mkrescue so
    // both files are inside the ISO.
    if !sh(
        root,
        "docker",
        &[
            "run",
            "--rm",
            "-v",
            &format!("{}:/work", iso_root.display()),
            TOOLS_IMAGE,
            "sh",
            "-c",
            GRUB_ARTIFACTS_SH,
        ],
    ) {
        return false;
    }
    sh(
        root,
        "docker",
        &[
            "run",
            "--rm",
            "-v",
            &format!("{}:/work", iso_root.display()),
            TOOLS_IMAGE,
            "grub-mkrescue",
            "-o",
            "/work/os.iso",
            "/work",
        ],
    )
}

/// Standard QEMU arguments for booting `iso` headless with serial on
/// stdio **and an HMP monitor on `monitor`** (a
/// `tcp:HOST:PORT,server,nowait` spec — see [`monitor_port`]).
///
/// Why a TCP monitor endpoint: serial stdio is already taken by the
/// console, so key injection (`sendkey`) needs a second channel, and
/// the first choice — a unix socket in the iso dir — was **verified
/// not to work** here: Docker Desktop does not relay unix-socket
/// connections through bind mounts (the socket file appears on the
/// host, but `connect(2)` gets `ECONNREFUSED`; probed 2026-11-21).
/// TCP does: the container publishes the port to the host loopback.
/// The bind host therefore differs by backend — Docker publishes to
/// the container's *eth0*, so QEMU must bind `0.0.0.0` inside (a
/// service on the container's loopback is unreachable via `-p`),
/// while a host QEMU binds `127.0.0.1` directly.
fn qemu_std_args(iso: &str, monitor: &str) -> Vec<String> {
    qemu_std_args_ex(iso, monitor, "stdio", None)
}

/// [`qemu_std_args_ex`] with the serial destination and an optional
/// `hostfwd` rule (S5's two-VM harness: the server VM publishes guest
/// :2222 on the container's loopback, so the client VM's slirp gateway
/// `10.0.2.2:2222` reaches it). `serial` is a QEMU chardev spec —
/// `stdio` for the observed VM, `file:/path` for the background one.
fn qemu_std_args_ex(
    iso: &str,
    monitor: &str,
    serial: &str,
    hostfwd: Option<(&str, u16, u16)>,
) -> Vec<String> {
    let rules: Vec<(&str, u16, u16)> = hostfwd.into_iter().collect();
    qemu_std_args_fw(iso, monitor, serial, &rules)
}

/// [`qemu_std_args_ex`] with **any number of** `hostfwd` rules
/// (hwtest needs two: the sshd forward :2223→:2222 *and* the netlog
/// forward :2224→:2224 on the same slirp netdev). Empty slice = no
/// forwards, exactly like `None`.
fn qemu_std_args_fw(
    iso: &str,
    monitor: &str,
    serial: &str,
    hostfwds: &[(&str, u16, u16)],
) -> Vec<String> {
    let mut args = vec![
        "-m".into(),
        "256M".into(),
        "-cdrom".into(),
        iso.into(),
        // Boot the ISO *first*, then the disk (`d` = first CD-ROM,
        // `c` = first hard disk in QEMU's legacy order letters). Since
        // FS1, an attached smoke disk carries a genuine FAT boot sector
        // at LBA0 (0x55 AA + a valid jump), which SeaBIOS is happy to
        // execute — verified in the FS1 milestone: with QEMU's default
        // order the guest hangs in the volume's bootstrap and the ISO
        // never boots. Pinning the ISO first keeps both smokes on GRUB
        // while `-boot order=c` (the I1b disk-boot phase) boots the
        // installed target alone.
        "-boot".into(),
        "order=dc".into(),
    ];
    args.extend(qemu_device_args_fw(serial, monitor, hostfwds));
    args
}

/// The I1b **disk-boot** QEMU arguments: no ISO at all, `-boot order=c`
/// so SeaBIOS executes the target disk's GRUB `boot.img` from LBA0.
/// The device set is identical to [`qemu_std_args_ex`] (e1000 for the
/// kernel's network chain, UHCI + usb-kbd for the USB proof) — the
/// installed kernel runs its normal boot chain, so the disk-boot proof
/// exercises the same hardware path the ISO smoke does.
fn qemu_disk_args(monitor: &str) -> Vec<String> {
    let mut args = vec!["-m".into(), "256M".into(), "-boot".into(), "order=c".into()];
    args.extend(qemu_device_args("stdio", monitor, None));
    args
}

/// Everything after the boot medium: serial/monitor redirection,
/// display, and the devices every smoke expects (e1000 with a fixed
/// MAC, USB + boot keyboard). Shared by the ISO and disk invocations.
fn qemu_device_args(serial: &str, monitor: &str, hostfwd: Option<(&str, u16, u16)>) -> Vec<String> {
    let rules: Vec<(&str, u16, u16)> = hostfwd.into_iter().collect();
    qemu_device_args_fw(serial, monitor, &rules)
}

/// [`qemu_device_args`] with **any number of** `hostfwd` rules, all
/// on the same slirp netdev — QEMU takes them comma-separated
/// (`user,id=net0,hostfwd=…,hostfwd=…`). Empty slice = no forwards.
fn qemu_device_args_fw(serial: &str, monitor: &str, hostfwds: &[(&str, u16, u16)]) -> Vec<String> {
    let args = vec![
        "-serial".into(),
        serial.into(),
        "-monitor".into(),
        monitor.into(),
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        // User-mode networking (slirp): the e1000 TX/RX test needs a
        // peer that answers ARP (gateway 10.0.2.2). Explicit device
        // (with fixed MAC) instead of relying on QEMU's implicit default.
        "-netdev".into(),
        if hostfwds.is_empty() {
            "user,id=net0".into()
        } else {
            let mut spec = String::from("user,id=net0");
            for (host, host_port, guest_port) in hostfwds {
                spec.push_str(&format!(",hostfwd=tcp:{host}:{host_port}-:{guest_port}"));
            }
            spec
        },
        "-device".into(),
        "e1000,netdev=net0,mac=52:54:00:12:34:56".into(),
        // USB HID keyboard milestone: `-usb` creates QEMU's PIIX3 UHCI
        // companion (hw/i386/pc_piix.c passes machine_usb() to the
        // south bridge's `has-usb`; hw/isa/piix.c then realizes
        // `piix3-usb-uhci` at devfn+2 = 00:01.2, 8086:7020, I/O BAR4)
        // and `-device usb-kbd` attaches a boot keyboard to it — the
        // device the kernel's `usb::init` enumerates for USB_KBD_OK.
        // Verified empirically: without `-usb` QEMU rejects usb-kbd
        // ("No 'usb-bus' bus found"); with it, `info pci` shows the
        // controller at 00:01.2. `sendkey` still feeds PS/2, so the
        // KEYBOARD_OK phase is unaffected (keyboard.rs keeps PS/2
        // primary whenever an i8042 exists).
        "-usb".into(),
        "-device".into(),
        "usb-kbd".into(),
    ];
    args
}

fn host_qemu() -> bool {
    matches!(
        Command::new("qemu-system-x86_64").arg("--version").output(),
        Ok(o) if o.status.success()
    )
}

// ---------------------------------------------------------------------------
// A3 chat mock (docs/ai-client.md §7, row A3): the guest posts to
// 10.0.2.2:8099; libslirp maps that onto QEMU's *host* loopback
// (`sotranslate_out4` in libslirp: guest→gateway connects connect to
// 127.0.0.1 of the machine QEMU runs on). QEMU runs inside the
// `reemplazo-tools` container during the smoke, so the mock must be a
// process in that container — see [`mock_loop`]. The host-QEMU
// backend (no host QEMU exists today) gets the same mock as a child
// process ([`spawn_chat_mock`]) so both paths stay consistent.
// ---------------------------------------------------------------------------

/// Canned mock chat completion: a complete `HTTP/1.1 200` with
/// `application/json` and a **computed** `Content-Length` (never
/// hand-counted), carrying a realistic OpenAI-style completion. The
/// reply text is byte-identical to `CANNED_REPLY` in
/// `kernel/src/apps/ai.rs` — duplicated like `DISK_MAGIC`, because
/// xtask cannot depend on the `no_std` kernel crate.
fn chat_mock_response() -> Vec<u8> {
    const BODY: &str = concat!(
        r#"{"id":"chatcmpl-reemplazo-mock","object":"chat.completion","#,
        r#""created":1763712000,"model":"reemplazo-mock","#,
        r#""choices":[{"index":0,"message":{"role":"assistant","#,
        r#""content":"reemplazo: mock reply ok"},"finish_reason":"stop"}],"#,
        r#""usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}"#
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(BODY.as_bytes());
    response
}

/// Canned mock **streaming** completion (A4): a `text/event-stream`
/// body with three `delta.content` fragments and the `[DONE]`
/// terminator, served verbatim with a computed `Content-Length` (the
/// guest's parser needs a framed body — `nc` never closes before the
/// client does, so close-delimited would deadlock). The concatenated
/// fragments are byte-identical to `STREAM_REPLY` in
/// `kernel/src/apps/ai.rs` (duplicated like `CANNED_REPLY`).
fn chat_mock_sse_response() -> Vec<u8> {
    const BODY: &str = concat!(
        "data: {\"id\":\"chatcmpl-reemplazo-mock-sse\",\"object\":\"chat.completion.chunk\",",
        "\"created\":1763712000,\"model\":\"reemplazo-mock\",",
        "\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-reemplazo-mock-sse\",\"object\":\"chat.completion.chunk\",",
        "\"created\":1763712000,\"model\":\"reemplazo-mock\",",
        "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"reemplazo: \"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-reemplazo-mock-sse\",\"object\":\"chat.completion.chunk\",",
        "\"created\":1763712000,\"model\":\"reemplazo-mock\",",
        "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"streamed \"},\"finish_reason\":null}]}\n\n",
        "data: {\"id\":\"chatcmpl-reemplazo-mock-sse\",\"object\":\"chat.completion.chunk\",",
        "\"created\":1763712000,\"model\":\"reemplazo-mock\",",
        "\"choices\":[{\"index\":0,\"delta\":{\"content\":\"reply ok\"},\"finish_reason\":\"stop\"}]}\n\n",
        "data: [DONE]\n\n"
    );
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
         Cache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        BODY.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(BODY.as_bytes());
    response
}

/// Write `chat-mock-response.txt` into the ISO dir (bind-mounted at
/// `/iso` in the container, plain file for the host backend). Called
/// from [`qemu_invocation`], i.e. after `iso()` has wiped the dir (the
/// `disk.img` precedent) and before the VM starts — so it is never
/// inside the ISO itself, just beside it. A4 adds the SSE variant for
/// the streaming proof on `:8098`.
fn write_chat_mock(iso_dir: &Path) -> std::io::Result<()> {
    std::fs::write(iso_dir.join("chat-mock-response.txt"), chat_mock_response())?;
    std::fs::write(
        iso_dir.join("chat-mock-sse-response.txt"),
        chat_mock_sse_response(),
    )
}

// ---------------------------------------------------------------------------
// G6 push mock (docs/git-ssh-deps.md §A.4 row G6; milestone G5 in the
// plan): a **static** receive-pack responder. The advertisement is a
// canned smart-HTTP reply, the POST answer is the v0 `report-status`
// every git client expects, and the received request bytes are appended
// to `/iso/push-capture.bin` for the host-side pack check that runs
// after QEMU exits. Two ports, because one `nc` loop cannot choose its
// canned response by request method (documented deviation: a real
// server serves both on one origin).
// ---------------------------------------------------------------------------

/// The advertised `old` id. A real server advertises its own HEAD, which
/// a static in-container `nc` cannot know; the client echoes this
/// **obviously synthetic** placeholder as the command's `old` (the
/// protocol requires echoing the advertisement) and sends the local
/// commit's graph — exactly what a server already holding the fetched
/// head would need. The mock is not a repository; the pack is validated
/// for real on the host (`verify_pushed_pack`).
const PUSH_OLD_OID: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";

/// One pkt-line data packet (fixed small payloads: 4 hex + payload).
fn pkt_line(payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; payload.len() + 4];
    match git_pktline::encode_data(payload, &mut buf) {
        Some(len) => {
            buf.truncate(len);
            buf
        }
        None => Vec::new(),
    }
}

/// Canned `HTTP/1.1 200` with a computed `Content-Length` (never
/// hand-counted — the `chat_mock_response` rule).
fn canned_http(content_type: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

/// `# service=git-receive-pack` + flush + one ref with `report-status`
/// + flush (http-protocol advertisement, v0).
fn push_advertisement() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(b"# service=git-receive-pack\n"));
    body.extend_from_slice(b"0000");
    let mut line = Vec::new();
    line.extend_from_slice(PUSH_OLD_OID.as_bytes());
    line.extend_from_slice(b" refs/heads/main\0report-status\n");
    body.extend_from_slice(&pkt_line(&line));
    body.extend_from_slice(b"0000");
    canned_http("application/x-git-receive-pack-advertisement", &body)
}

/// `unpack ok` / `ok refs/heads/main` / flush — the report the kernel
/// asserts before it prints `GIT_PUSH_OK`.
fn push_ack() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&pkt_line(b"unpack ok\n"));
    body.extend_from_slice(&pkt_line(b"ok refs/heads/main\n"));
    body.extend_from_slice(b"0000");
    canned_http("application/x-git-receive-pack-result", &body)
}

/// Write the two canned push responses beside the ISO. The capture file
/// is *not* touched here (the `nc` loop appends to it), so a later
/// invocation (the installed-disk boot phase) cannot wipe the evidence
/// of the first one before it is validated.
fn write_push_mock(iso_dir: &Path) -> std::io::Result<()> {
    std::fs::write(iso_dir.join("push-advertisement.txt"), push_advertisement())?;
    std::fs::write(iso_dir.join("push-ack.txt"), push_ack())
}

/// Build the I2 payload the guest fetches with its own stack:
/// stage the **actual built kernel** (`target/x86_64-unknown-none/
/// release/kernel` — the system payload of docs/installer.md §6.1)
/// plus `README.TXT`, pack both into `payload.tar` with the host's
/// `tar --format ustar` (the format `install::parse_tar` walks — its
/// header bytes were pinned against exactly this tool, see
/// docs/installer.md §8.4), and wrap the tar in a canned
/// `HTTP/1.1 200` response (`payload-http.txt`) that the
/// in-container `nc` responder on `:8080` serves verbatim — the chat
/// mock's pattern with a real body. Called from [`qemu_invocation`]
/// (after `iso()`), so every boot path has it; nobody connects unless
/// the network installer runs.
fn write_payload_mock(root: &Path, iso_dir: &Path) -> std::io::Result<()> {
    let staging = iso_dir.join("payload-staging");
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)?;
    std::fs::copy(
        root.join("target/x86_64-unknown-none/release/kernel"),
        staging.join("kernel.elf"),
    )?;
    std::fs::write(staging.join("README.TXT"), README_CONTENT)?;

    let tar_path = iso_dir.join("payload.tar");
    let status = Command::new("tar")
        .args(["--format", "ustar", "-cf"])
        .arg(&tar_path)
        .arg("-C")
        .arg(&staging)
        // Arg order = entry order: README first (tiny), kernel second.
        .args(["README.TXT", "kernel.elf"])
        .status()?;
    if !status.success() {
        return Err(std::io::Error::other(format!(
            "tar --format ustar failed with {status}"
        )));
    }

    let tar = std::fs::read(&tar_path)?;
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        tar.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(&tar);
    std::fs::write(iso_dir.join("payload-http.txt"), response)
}

/// The G6 push mock: advertisement on `:8090`, the receive-pack ACK on
/// `:8091`, each a **bounded** loop of one-shot `nc` servers on the
/// container's loopback (two ports — see the section note above). The
/// ACK server **appends** every POST request to
/// `/iso/push-capture.bin`, which the host decodes after QEMU exits.
/// Both loops run for six connections: `smoke-install` needs one pair,
/// `smoke-ssh` boots two VMs that each push.
fn push_mock_loop() -> String {
    "for i in 1 2 3 4 5 6; do \
     nc -l -s 127.0.0.1 -p 8090 < /iso/push-advertisement.txt > /dev/null 2>&1 || true; \
     done & \
     for i in 1 2 3 4 5 6; do \
     nc -l -s 127.0.0.1 -p 8091 < /iso/push-ack.txt >> /iso/push-capture.bin 2>/dev/null || true; \
     done & "
        .to_string()
}

/// The in-container mock: a **bounded** loop of `nc` one-shot servers
/// on the container's loopback — `:8099` serves the canned chat
/// response, `:8098` the A4 canned **SSE** response (three deltas +
/// `[DONE]`), `:8080` serves the canned *payload* response (I2: the
/// guest's `GET /payload.tar` over its own stack) and [`push_mock_loop`]
/// adds the G6 receive-pack pair — backgrounded, then QEMU is
/// `exec`'d, so QEMU becomes the container's main process and, when the
/// container stops (`--rm` / `docker rm -f`), every process in it dies
/// with it: no host-side orphans, which this repo checks with `ps`
/// after every run. `nc` serves the canned response the moment a
/// connection is accepted (HTTP lets the server write first; the guest
/// sends-then-reads), exits per connection when the peer closes, and
/// `|| true` keeps the loop running through a refused bind.
/// stdout/stderr of the chat/payload servers → `/dev/null` so request
/// bytes can never pollute the serial log the markers are read from.
fn mock_loop() -> String {
    format!(
        "{}for i in 1 2 3 4 5; do \
         nc -l -s 127.0.0.1 -p 8099 < /iso/chat-mock-response.txt > /dev/null 2>&1 || true; \
         done & \
         for i in 1 2 3 4 5; do \
         nc -l -s 127.0.0.1 -p 8098 < /iso/chat-mock-sse-response.txt > /dev/null 2>&1 || true; \
         done & \
         for i in 1 2 3 4 5; do \
         nc -l -s 127.0.0.1 -p 8080 < /iso/payload-http.txt > /dev/null 2>&1 || true; \
         done & exec qemu-system-x86_64 \"$@\"",
        push_mock_loop()
    )
}

/// The `xtask chat-mock` subcommand (host-QEMU backend): serve
/// [`chat_mock_response`] on 127.0.0.1:8099, the I2 payload response on
/// 127.0.0.1:8080 and the G6 push responses on 8090/8091 (the container
/// backend's [`mock_loop`] does the same four ports with `nc`), for a
/// bounded number of connections and a bounded lifetime, so a wedged
/// guest can never leave this process running on its own. The 8091
/// server reads the POST body and appends it to
/// `target/iso-root/push-capture.bin` — the host backend's equivalent of
/// `nc >> /iso/push-capture.bin`. Spawned as a child by
/// [`qemu_invocation`] and killed in `stop_vm`; also reachable manually
/// for debugging against a host VM.
fn serve_chat_mock(root: &Path) {
    let iso_dir = root.join("target/iso-root");
    let file = iso_dir.join("chat-mock-response.txt");
    let chat = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read {}: {e}", file.display());
            exit(1);
        }
    };
    let sse_file = root.join("target/iso-root/chat-mock-sse-response.txt");
    let sse = match std::fs::read(&sse_file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read {}: {e}", sse_file.display());
            exit(1);
        }
    };
    let payload = match std::fs::read(root.join("target/iso-root/payload-http.txt")) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read payload-http.txt: {e}");
            exit(1);
        }
    };
    let push_adv = match std::fs::read(iso_dir.join("push-advertisement.txt")) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read push-advertisement.txt: {e}");
            exit(1);
        }
    };
    let push_ack = match std::fs::read(iso_dir.join("push-ack.txt")) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read push-ack.txt: {e}");
            exit(1);
        }
    };
    let mut listeners = Vec::new();
    for port in [8099u16, 8098, 8080, 8090, 8091] {
        match std::net::TcpListener::bind(("127.0.0.1", port)) {
            Ok(listener) => {
                if listener.set_nonblocking(true).is_err() {
                    exit(1);
                }
                listeners.push((port, listener));
            }
            Err(e) => {
                eprintln!("xtask chat-mock: cannot bind 127.0.0.1:{port}: {e}");
                exit(1);
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut served = 0usize;
    while served < 16 && Instant::now() < deadline {
        let mut connected = false;
        for (port, listener) in &listeners {
            let (mut stream, _) = match listener.accept() {
                Ok(pair) => pair,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => {
                    eprintln!("xtask chat-mock: accept failed: {e}");
                    continue;
                }
            };
            connected = true;
            let _ = stream.set_nonblocking(true); // no client can wedge us
            match *port {
                8098 => {
                    let _ = stream.write_all(&sse);
                    drain_briefly(&mut stream);
                }
                8099 => {
                    let _ = stream.write_all(&chat);
                    drain_briefly(&mut stream);
                }
                8080 => {
                    let _ = stream.write_all(&payload);
                    drain_briefly(&mut stream);
                }
                8090 => {
                    let _ = stream.write_all(&push_adv);
                    drain_briefly(&mut stream);
                }
                _ => {
                    // Read the whole POST before answering, so the
                    // capture has the pack (the `nc` redirect's job in
                    // the container backend).
                    if let Some(request) = read_http_request(&mut stream) {
                        append_capture(&iso_dir.join("push-capture.bin"), &request);
                    }
                    let _ = stream.write_all(&push_ack);
                    drain_briefly(&mut stream);
                }
            }
            served += 1;
        }
        if !connected {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// Read one HTTP request (head + `Content-Length` body) from a
/// nonblocking stream, bounded in bytes and time.
fn read_http_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
    const CAP: usize = 4 * 1024 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let mut want: Option<usize> = None;
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > CAP {
                    return None;
                }
                if want.is_none()
                    && let Some(sep) = buf.windows(4).position(|w| w == b"\r\n\r\n")
                    && let Some(len) = header_content_length(&buf[..sep])
                {
                    want = Some(sep.checked_add(4)?.checked_add(len)?);
                }
                if let Some(total) = want
                    && buf.len() >= total
                {
                    buf.truncate(total);
                    return Some(buf);
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(_) => break,
        }
    }
    None
}

/// `Content-Length` from a complete HTTP head (the xtask mock's own
/// request reader; the kernel does not use this). Lines without a colon
/// (the request line) and the terminating empty line are skipped.
fn header_content_length(head: &[u8]) -> Option<usize> {
    for line in head.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if line.is_empty() {
            break;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        if line[..colon].eq_ignore_ascii_case(b"content-length") {
            return std::str::from_utf8(&line[colon + 1..])
                .ok()?
                .trim()
                .parse()
                .ok();
        }
    }
    None
}

/// Append a captured request to `path` (the `nc >> file` equivalent).
fn append_capture(path: &Path, bytes: &[u8]) {
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = file.write_all(bytes);
    }
}

/// Best-effort drain of a request, bounded in time (closing with unread
/// inbound data sends RST, which can discard the response).
fn drain_briefly(stream: &mut TcpStream) {
    let mut buf = [0u8; 512];
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match stream.read(&mut buf) {
            Ok(0) => break, // peer finished — clean close
            Ok(_) => {}
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

/// Spawn [`serve_chat_mock`] as this xtask's child (host-QEMU
/// backend). `stderr` inherits so a bind failure is visible; stdout
/// is silent. Killed in `stop_vm` — the orphan discipline applies to
/// it as much as to QEMU.
fn spawn_chat_mock(root: &Path) -> Option<Child> {
    let exe = match std::env::current_exe() {
        Ok(exe) => exe,
        Err(e) => {
            eprintln!("xtask: cannot locate self for chat-mock: {e}");
            return None;
        }
    };
    match Command::new(exe)
        .arg("chat-mock")
        .current_dir(root)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .spawn()
    {
        Ok(child) => Some(child),
        Err(e) => {
            eprintln!("xtask: cannot spawn chat-mock: {e}");
            None
        }
    }
}

/// What to launch: `(program, args, container_name, mock_child)` —
/// see [`qemu_invocation`].
type Invocation = (String, Vec<String>, Option<String>, Option<Child>);

/// `(program, args, container_name, mock_child)` to boot `iso_path`;
/// every path in `disks` is attached as a raw IDE drive, in order —
/// first = master (unit 0), second = slave (unit 1) on the legacy
/// primary channel, which is exactly how `ata::probe`/
/// `ata::probe_target` enumerate them (empty for `smoke`/`run`, two
/// for `smoke-install`: the FAT16 source then the blank target). The
/// images live beside `os.iso`, so the container sees them at
/// `/iso/<name>`. Host QEMU first; otherwise build the toolchain image
/// and run in Docker. `container` is the fixed name used for
/// force-cleanup of stale VMs. `mock_child` is the A3 chat mock on the
/// host backend only (the container backend runs [`mock_loop`] inside
/// itself) — every caller must kill it, which `stop_vm` does.
/// Both backends get an HMP monitor on this checkout's [`monitor_port`]:
/// host QEMU binds `127.0.0.1` itself, the container publishes its
/// `0.0.0.0` listener with `-p 127.0.0.1:PORT:PORT`.
fn qemu_invocation(
    root: &Path,
    iso_path: &Path,
    container: &str,
    disks: &[&Path],
    ahci_disks: &[&Path],
) -> Option<Invocation> {
    // The A3 mock response and the I2 payload response must exist
    // before the VM starts: written after `iso()` wiped the dir (the
    // `disk.img` precedent).
    let iso_dir = iso_path.parent()?;
    if let Err(e) = write_chat_mock(iso_dir) {
        eprintln!(
            "xtask: cannot write {}: {e}",
            iso_dir.join("chat-mock-response.txt").display()
        );
        return None;
    }
    if let Err(e) = write_push_mock(iso_dir) {
        eprintln!("xtask: cannot write the push mock: {e}");
        return None;
    }
    // A new VM means a new capture; the previous boot's file must not
    // be read back as this one's. (The installed-disk phase is a boot
    // too, but it validates first.)
    let _ = std::fs::remove_file(iso_dir.join("push-capture.bin"));
    if let Err(e) = write_payload_mock(root, iso_dir) {
        eprintln!("xtask: cannot build the payload mock: {e}",);
        return None;
    }
    let port = monitor_port(root);
    if host_qemu() {
        let iso = iso_path.display().to_string();
        let monitor = format!("tcp:127.0.0.1:{port},server,nowait");
        let mut args = qemu_std_args(&iso, &monitor);
        for d in disks {
            args.push("-drive".into());
            args.push(format!("file={},if=ide,format=raw", d.display()));
        }
        // AHCI disks: one `ich9-ahci` controller, each disk on its own
        // port (bus 1..) — the MacBook's real transport.
        if !ahci_disks.is_empty() {
            args.push("-device".into());
            args.push("ich9-ahci,id=sata".into());
        }
        for (i, d) in ahci_disks.iter().enumerate() {
            args.push("-drive".into());
            args.push(format!(
                "file={},if=none,id=ahci{i},format=raw",
                d.display()
            ));
            args.push("-device".into());
            args.push(format!("ide-hd,drive=ahci{i},bus=sata.{}", i + 1));
        }
        let mock = spawn_chat_mock(root);
        return Some(("qemu-system-x86_64".into(), args, None, mock));
    }
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return None;
    }
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--name".into(),
        container.into(),
        "-v".into(),
        format!("{}:/iso", iso_dir.display()),
        // Publish the monitor to the host loopback (see `qemu_std_args`:
        // QEMU binds the container's 0.0.0.0, `-p` forwards to eth0).
        "-p".into(),
        format!("127.0.0.1:{port}:{port}"),
        TOOLS_IMAGE.into(),
        // A3 chat mock + QEMU as one container command: `sh -c` runs
        // the bounded nc loop in the background (it must live in this
        // container — slirp sends guest→10.0.2.2:8099 to *QEMU's
        // host* loopback) and `exec`s QEMU with the args below as
        // "$@" ($0 carries the binary name).
        "sh".into(),
        "-c".into(),
        mock_loop(),
        "qemu-system-x86_64".into(),
    ];
    let monitor = format!("tcp:0.0.0.0:{port},server,nowait");
    args.extend(qemu_std_args("/iso/os.iso", &monitor));
    for d in disks {
        // The iso dir is bind-mounted at /iso and the images were
        // created inside it (see `smoke_install`), so they're visible
        // at /iso/<name>.
        let name = d.file_name()?.to_str()?;
        args.push("-drive".into());
        args.push(format!("file=/iso/{name},if=ide,format=raw"));
    }
    if !ahci_disks.is_empty() {
        args.push("-device".into());
        args.push("ich9-ahci,id=sata".into());
    }
    for (i, d) in ahci_disks.iter().enumerate() {
        let name = d.file_name()?.to_str()?;
        args.push("-drive".into());
        args.push(format!("file=/iso/{name},if=none,id=ahci{i},format=raw"));
        args.push("-device".into());
        args.push(format!("ide-hd,drive=ahci{i},bus=sata.{}", i + 1));
    }
    Some(("docker".into(), args, Some(container.into()), None))
}

/// [`qemu_invocation`] for the **disk-boot phase** (I1b): no ISO, the
/// installed `target.img` as the only IDE disk, `-boot order=c`. The A3
/// chat mock is still started (the installed kernel runs its normal,
/// fail-closed boot chain, and `apps::ai` halts without the mock) — the
/// in-container `mock_loop` comes along with the same bind mount; the
/// host backend's `chat-mock` child serves both ports. Everything else
/// (serial on stdout, one monitor, e1000, USB) matches [`qemu_invocation`].
fn qemu_invocation_disk(
    root: &Path,
    iso_dir: &Path,
    container: &str,
    disk: &Path,
) -> Option<Invocation> {
    if let Err(e) = write_chat_mock(iso_dir) {
        eprintln!(
            "xtask: cannot write {}: {e}",
            iso_dir.join("chat-mock-response.txt").display()
        );
        return None;
    }
    // Responses only: the capture of the *install* boot is validated
    // before this phase ever runs, and this boot has no source disk, so
    // deleting it here would only destroy evidence.
    if let Err(e) = write_push_mock(iso_dir) {
        eprintln!("xtask: cannot write the push mock: {e}");
        return None;
    }
    if let Err(e) = write_payload_mock(root, iso_dir) {
        eprintln!("xtask: cannot build the payload mock: {e}");
        return None;
    }
    // Second monitor port: the install VM's QEMU has already been
    // stopped, but keeping the two invocations on distinct ports makes
    // a leaked process impossible to confuse with the next phase.
    let port = monitor_port_n(root, 2);
    if host_qemu() {
        let monitor = format!("tcp:127.0.0.1:{port},server,nowait");
        let mut args = qemu_disk_args(&monitor);
        args.push("-drive".into());
        args.push(format!("file={},if=ide,format=raw", disk.display()));
        let mock = spawn_chat_mock(root);
        return Some(("qemu-system-x86_64".into(), args, None, mock));
    }
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return None;
    }
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--name".into(),
        container.into(),
        "-v".into(),
        format!("{}:/iso", iso_dir.display()),
        "-p".into(),
        format!("127.0.0.1:{port}:{port}"),
        TOOLS_IMAGE.into(),
        "sh".into(),
        "-c".into(),
        mock_loop(),
        "qemu-system-x86_64".into(),
    ];
    let monitor = format!("tcp:0.0.0.0:{port},server,nowait");
    args.extend(qemu_disk_args(&monitor));
    let name = disk.file_name()?.to_str()?;
    args.push("-drive".into());
    args.push(format!("file=/iso/{name},if=ide,format=raw"));
    Some(("docker".into(), args, Some(container.into()), None))
}

/// Remove a container by name if present (stale VM from a killed session).
fn rm_container(name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stop_vm(child: &mut Child, container: Option<&str>, mock: &mut Option<Child>) {
    let _ = child.kill();
    let _ = child.wait();
    if let Some(name) = container {
        rm_container(name);
    }
    // The host-backend chat mock (the container backend's mock dies
    // with its container) — killed on every exit path, no orphans.
    if let Some(mock) = mock {
        let _ = mock.kill();
        let _ = mock.wait();
    }
}

fn run(root: &Path) -> bool {
    if !iso(root) {
        return false;
    }
    let iso_path = root.join("target/iso-root/os.iso");
    let Some((prog, args, container, mut mock)) =
        qemu_invocation(root, &iso_path, &vm_container(root, "run"), &[], &[])
    else {
        return false;
    };
    if let Some(name) = &container {
        rm_container(name); // stale VM from a previous Ctrl-C
    }
    // The keyboard path besides the serial console: inject keys through
    // QEMU's HMP monitor (`sendkey`), e.g.
    //   printf 'sendkey h\nsendkey i\nret\n' | nc 127.0.0.1 <port>
    // Letters are key names as-is, `spc` is space, `ret` is Enter and
    // `shift-k` types an uppercase K (QEMU's QKeyCode names).
    let port = monitor_port(root);
    println!("xtask: QEMU monitor on 127.0.0.1:{port} — type keys with e.g.");
    println!("  printf 'sendkey h\\nsendkey i\\nret\\n' | nc 127.0.0.1 {port}");
    let status = Command::new(&prog).args(&args).current_dir(root).status();
    if let Some(name) = &container {
        rm_container(name);
    }
    if let Some(mock) = mock.as_mut() {
        let _ = mock.kill();
        let _ = mock.wait();
    }
    match status {
        Ok(s) if s.success() => true,
        Ok(s) => {
            eprintln!("xtask: qemu exited with {s}");
            false
        }
        Err(e) => {
            eprintln!("xtask: cannot start {prog}: {e}");
            false
        }
    }
}

/// `cargo xtask smoke-netinstall-real` — host-side **preflight** for the
/// real HTTPS payload source used by `install::netprove_https`
/// (docs/installer.md §8.8). It is deliberately NOT a QEMU smoke: the
/// kernel entry point is opt-in (the shell/hardware integrator wires
/// it), so this command only proves the endpoint's *current* shape with
/// the exact headers the kernel will send — status 200, raw media type,
/// no redirect — and prints what is still required for the end-to-end
/// hardware proof. No mocks, no credentials, no disk is touched and no
/// existing smoke marker is affected.
fn smoke_netinstall_real(_root: &Path) -> bool {
    // Duplicated on purpose: host crates cannot depend on the kernel.
    const URL: &str =
        "https://api.github.com/repos/LuisErnestoZamb/reemplazo/contents/payload.tar?ref=main";
    println!("smoke-netinstall-real: endpoint {URL}");
    println!(
        "smoke-netinstall-real: GET with User-Agent + Accept: application/vnd.github.raw, no credentials"
    );
    let output = Command::new("curl")
        .args([
            "-sS",
            "--max-time",
            "20",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code} %{content_type} %{num_redirects}",
            "-H",
            "Accept: application/vnd.github.raw",
            "-H",
            "User-Agent: reemplazo-netinstall/0.1",
            "-H",
            "X-GitHub-Api-Version: 2022-11-28",
            URL,
        ])
        .output();
    let output = match output {
        Ok(output) => output,
        Err(e) => {
            eprintln!("smoke-netinstall-real: cannot run curl: {e}");
            return false;
        }
    };
    if !output.status.success() {
        eprintln!(
            "smoke-netinstall-real: curl failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        return false;
    }
    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    println!("smoke-netinstall-real: status/content-type/redirects = {line}");
    let fields: Vec<&str> = line.split_whitespace().collect();
    let ok = fields.first() == Some(&"200")
        && fields.last() == Some(&"0")
        && fields.iter().any(|f| f.contains("raw"));
    if ok {
        println!(
            "smoke-netinstall-real: PASS (host preflight only) — kernel TLS/JSON/tar path \
             still needs the payload published at that path and a real-hardware run"
        );
    } else if fields.first() == Some(&"404") {
        eprintln!(
            "smoke-netinstall-real: 404 — publish payload.tar at that repo path before \
             the real installer can fetch it; the mock netprove remains the CI gate"
        );
    } else {
        eprintln!(
            "smoke-netinstall-real: FAIL — expected HTTP 200 with the raw media type and zero redirects"
        );
    }
    ok
}

/// Machine-checked boot test: boot the ISO headless and require each
/// milestone's serial marker in order — `BOOT_OK` (Multiboot2 parse),
/// `MEM_OK` (frame-allocator selftest), `ALLOC_OK` (kernel heap: `Vec`
/// push/check/drop round-trip), `PCI_OK` (config scan),
/// `USB_KBD_OK` (UHCI probe + HID boot-keyboard enumeration,
/// configuration and one live interrupt-IN poll),
/// `E1000_OK` (NIC probe + MMIO + MAC), `NET_OK` (TX/RX rings + ARP
/// roundtrip through slirp), `PING_OK` (IPv4/ICMP echo with validated
/// checksums), `DHCP_OK` (full DISCOVER/OFFER/REQUEST/ACK lease),
/// `DNS_OK` (RFC 1035 A lookup for github.com through the leased
/// server), `TCP_OK` (RFC 9293 connect + HTTP GET + FIN close against
/// github.com:80), `INT_OK` (IDT + PIC remap + PIT ticks + int3
/// resume), `TUI_OK` (A1 screen layer: the demo frame rendered into
/// the VGA text buffer and read back from `0xb8000`), `EDITOR_OK` (A2
/// editor: scripted insert/newline/delete/undo/redo edits rendered
/// with the line-number gutter and status bar, read back from
/// `0xb8000`), `AI_CHAT_OK` (A3 chat client: OpenAI-style POST against
/// the in-container mock, serde_json reply parsed, the conversation
/// pane read back from `0xb8000`), `BROWSER_FETCH_OK` (B1 browser
/// fetch: URL parsed with `url`, `http://github.com/…` fetched through
/// a real 301 redirect over plain + TLS, bounded body counted),
/// `AI_EDIT_OK` (A5 editor ↔ AI: the mock completion applied into the
/// retained editor buffer through the `ai apply` path, undo/redo
/// round-trip asserted on the buffer, the editor frame read back from
/// `0xb8000`), `BROWSER_RENDER_OK` (B2 browser render: `example.com`
/// fetched through the parameterized B1 fetch, the `dom` arena tree
/// built over our tokenizer, the text layout — title bar, word-wrapped
/// paragraph, status URL — rendered in the TUI viewport and read back
/// from `0xb8000`, plus a fixture frame asserting headings, list
/// markers, `<pre>` whitespace, dim code, inverse link cells and the
/// `display:none` skip), `BROWSER_CSS_OK` (B3 CSS subset: the
/// kernel-owned styled fixture parsed by `csscore`, cascaded with
/// specificity/source-order/inline precedence, rendered and read back
/// from `0xb8000` — exact VGA attribute bytes for `color`,
/// `background-color` and `font-weight`, the margin/padding cell shift,
/// `display:none` absence — then the same body without its sheet,
/// proving the defaults return; the real page's own sheet is applied
/// as a robustness pass), `BROWSER_NAV_OK` (B4 navigation: the
/// interactive browser's own state driven through the keyboard path —
/// two kernel-owned fixture pages followed/back/forward with history
/// depths asserted, and an unreachable endpoint rendering the error
/// page instead of halting; offline, no internet needed), `SHELL_OK`
/// (the shell's prompt loop) and — only when `user/hello/` produced the
/// module staged by [`stage_hello_module`] — `ELF_OK` (U1: the `hello`
/// multiboot2 module parsed as ET_EXEC with all `PT_LOAD` pages mapped
/// user-accessible in a private PML4, plus user/kernel stacks) — within
/// [`SMOKE_TIMEOUT`]. Then the keyboard milestone:
/// once `SHELL_OK` matches, connect to QEMU's HMP monitor
/// ([`monitor_port`]) and type `echo KEYBOARD_OK` key by key with
/// `sendkey`, requiring the `KEYBOARD_OK` line the **shell's echo
/// builtin printed** within [`KEYBOARD_PHASE_TIMEOUT`] — an exact-line
/// match, so the echoed keystrokes alone (the same characters appear
/// in the input echo) cannot satisfy it. That proves i8042 → set-1
/// decode → line discipline → builtin end to end.
///
/// This is the test that fails on a broken boot path (header, trampoline,
/// GDT, paging, mbi parse), the VGA text mirror, memory path, heap path
/// (carve + global allocator), PCI scan, UHCI enumeration (HID boot
/// keyboard via `usbwire` + `kernel/src/usb.rs`), e1000 driver, network path,
/// DHCP/DNS/TCP clients, TLS and HTTP clients, git ls-remote and git
/// fetch (smart-HTTP want/deepen/done POST, `git-pack` decode, tree
/// walk), interrupt path (IDT,
/// stubs, EOI, timer), the A1 screen layer (cell diff flush into the
/// text buffer, ratatui backend, full-screen frame readback), the A2
/// editor (gap buffer + line index edits with undo/redo, viewport frame
/// readback), the A3 chat client (serde_json request/response over
/// `net::http` POST against the mock + chat-pane readback), the B1
/// browser fetch (URL parse/resolve + redirect-following HTTP(S) GET
/// against github.com), the A5 editor ↔ AI integration (retained
/// document, completion apply + undo round-trip, editor-frame
/// readback), the B2 browser render (HTML tree builder over the
/// tokenizer, text layout — wrap/heads/lists/pre/links — and the
/// viewport frame read back from `0xb8000`), the B3 CSS subset (sheet
/// parsing, specificity/source-order/inline cascade, VGA attribute
/// mapping and the styled-vs-unstyled fixture pair read back from
/// `0xb8000`), the B4 navigation state (fixture link follow through
/// `Url::join`, the bounded history's back/forward depths and the
/// forward-tail rule, the error page rendered for an unreachable
/// endpoint — all read back from `0xb8000`; offline), the serial
/// shell coming up, or the keyboard path (i8042 bring-up, scancode
/// decode, input multiplexing) — so it gates every milestone in the
/// chain.
///
/// It runs **without a disk**, so the `ata::probe` that sits between
/// `PCI_OK` and `E1000_OK` stays silent here.
/// `cargo xtask hwtest` — prove the **hardware bring-up path** in
/// QEMU: the ISO carries the `sshd` multiboot2 module, so the kernel
/// skips the smoke chain, takes a static address (plus the slirp one,
/// so `hostfwd` reaches it), serves sshd on guest :2222 and serves
/// **netlog** on guest :2224 (the serial ring over TCP); xtask then
/// runs the container's **real OpenSSH client** through
/// `hostfwd=tcp:0.0.0.0:2223-:2222` and requires the exec output,
/// and connects to `hostfwd=tcp:0.0.0.0:2224-:2224` to require the
/// known boot lines out of the netlog stream (`hwtest: netlog PASS
/// — <n> bytes`). Both are required for this harness to PASS. The
/// server's serial (with every drop/auth reason — the exact
/// diagnosis the real MacBook needs) is printed live as `hwtest| …`.
fn hwtest(root: &Path) -> bool {
    if !iso_inner(root, true, false) {
        return false;
    }
    let iso_dir = root.join("target/iso-root");
    let container = vm_container(root, "hwtest");
    rm_container(&container); // stale VM from a killed session
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return false;
    }
    let args = qemu_std_args_fw(
        "/iso/os.iso",
        &format!("tcp:127.0.0.1:{},server,nowait", monitor_port(root)),
        "stdio",
        // Two forwards on the same slirp netdev: the sshd repro
        // harness (:2223 → guest :2222) and netlog (:2224 → guest
        // :2224, the serial ring over TCP).
        &[("0.0.0.0", 2223, 2222), ("0.0.0.0", 2224, 2224)],
    );
    let mut docker_args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--name".into(),
        container.clone(),
        "-v".into(),
        format!("{}:/iso", iso_dir.display()),
        TOOLS_IMAGE.into(),
        "sh".into(),
        "-c".into(),
        String::from("exec qemu-system-x86_64 \"$@\""),
        "qemu-system-x86_64".into(),
    ];
    docker_args.extend(args.iter().cloned());
    let mut child = match Command::new("docker")
        .args(&docker_args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("xtask hwtest: cannot start docker: {e}");
            rm_container(&container);
            return false;
        }
    };
    let rx = spawn_line_reader(&mut child);
    let mut collected: Vec<String> = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut listening = false;
    while let Ok(line) = rx.recv_timeout(
        deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1)),
    ) {
        println!("hwtest| {line}");
        collected.push(line.clone());
        if line.contains("SSHD_LISTEN_OK") {
            listening = true;
            break;
        }
        if line.contains("FATAL") {
            break;
        }
    }
    let mut ok = false;
    let mut netlog_ok = false;
    if listening {
        // 0. netlog first (milestone netlog): the serial ring served
        //    over TCP on guest :2224. The kernel is inside the sshd
        //    accept window below — polling the stack, which is exactly
        //    what pumps the ring — so the history (boot lines) plus a
        //    live tail are available right now.
        match netlog_probe(&container) {
            Ok(bytes) => {
                netlog_ok = true;
                println!("hwtest: netlog PASS — {bytes} bytes over 2 sessions");
            }
            Err(e) => eprintln!("hwtest: netlog FAIL — {e}"),
        }
        // 1. An abrupt mid-KEX connection (open the TCP stream, say
        //    nothing, hang up): the server's step deadline fires and
        //    stores the failure reason — the input the banner replay
        //    below must surface. Keeps the failure path exercised on
        //    every run.
        let _ = Command::new("docker")
            .args([
                "exec",
                &container,
                "bash",
                "-c",
                "exec 3<>/dev/tcp/127.0.0.1/2223 && sleep 0.3 && exec 3>&-",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        // 2. Let the server's step deadline (OP_DEADLINE_MS = 10 s)
        //    fire and `remember_fail` before the replay connection.
        std::thread::sleep(Duration::from_secs(12));
        // 3. Drain the server's serial CONTINUOUSLY while the interop
        //    runs: each failed attempt's reason (step deadline = 10 s)
        //    must land in this log even when it fires seconds later.
        eprintln!("hwtest-diag: collector starting");
        let collector = std::thread::spawn(move || {
            let mut during = Vec::new();
            let mut quiet = 0u32;
            loop {
                match rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(line) => {
                        quiet = 0;
                        println!("hwtest| {line}");
                        during.push(line);
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        quiet += 1;
                        // The interop's last phase can be quiet; stop
                        // only after 30 s of silence (well past it).
                        if quiet >= 15 {
                            eprintln!("hwtest-diag: collector quiet-exit");
                            break;
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        eprintln!("hwtest-diag: collector DISCONNECTED (all senders gone)");
                        break;
                    }
                }
            }
            during
        });
        ok = run_openssh_interop(&container, "2223");
        if let Ok(extra) = collector.join() {
            eprintln!("hwtest-diag: collector delivered {} lines", extra.len());
            collected.extend(extra);
        } else {
            eprintln!("hwtest-diag: collector panicked");
        }
    } else {
        eprintln!("hwtest: the kernel never printed SSHD_LISTEN_OK");
    }
    let _ = child.kill();
    let _ = child.wait();
    rm_container(&container);
    if ok && netlog_ok {
        println!(
            "hwtest: PASS — real OpenSSH authenticated over hostfwd; netlog served the serial ring"
        );
    } else if ok {
        eprintln!("hwtest: FAIL — OpenSSH interop passed but netlog did not (see above)");
    } else {
        eprintln!("hwtest: FAIL — see the hwtest| server lines above");
        for line in &collected {
            if line.contains("sshd") || line.contains("FATAL") || line.contains("hw:") {
                eprintln!("hwtest| {line}");
            }
        }
    }
    ok && netlog_ok
}

/// One netlog session: connect to the guest's serial-over-TCP port
/// from **inside** the container (`hostfwd=tcp:0.0.0.0:2224-:2224`
/// binds the container's own interfaces, so `/dev/tcp/127.0.0.1:2224`
/// reaches it) and read for `secs` bounded seconds — the stream never
/// ends on its own (the server keeps streaming the live tail until
/// the client hangs up, which is what `timeout … cat` does), so the
/// timeout kill is the *expected* end of an open-ended stream and the
/// verdict is the content, not the exit status.
///
/// Returns the byte count when the stream carries a known boot line
/// (`hw: bring-up mode` or `BOOT_OK`); a detailed error — bytes
/// received plus the first lines — otherwise. `session` names the
/// attempt in the error (the second connection is the regression the
/// live hardware hit: after one client comes and goes the service
/// must still deliver bytes to the next one).
fn netlog_session(container: &str, session: &str, secs: u32) -> Result<usize, String> {
    // bash provides /dev/tcp (the same idiom the sshd phases use),
    // coreutils provides `timeout`. Exit 11 = connect refused.
    let script = format!("exec 3<>/dev/tcp/127.0.0.1/2224 || exit 11; timeout {secs} cat <&3");
    let out = match Command::new("docker")
        .args(["exec", container, "bash", "-c", &script])
        .output()
    {
        Ok(out) => out,
        Err(e) => return Err(format!("{session}: cannot run docker exec: {e}")),
    };
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.stdout.is_empty() {
        return Err(format!(
            "{session}: 0 bytes received (status: {}; stderr: {})",
            out.status,
            stderr.trim()
        ));
    }
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("hw: bring-up mode") && !text.contains("BOOT_OK") {
        let head: String = text.lines().take(8).map(|l| format!("  {l}\n")).collect();
        return Err(format!(
            "{session}: {} bytes received but no known boot line; first lines:\n{head}",
            out.stdout.len()
        ));
    }
    Ok(out.stdout.len())
}

/// The netlog phase: **two fast connect-and-hang-up rounds** followed
/// by **two reading sessions** against the guest's serial-over-TCP
/// port.
///
/// The fast rounds are what `nc -z` does on the live MacBook: the
/// handshake's final ACK and the FIN arrive back-to-back, and with
/// the accept loop napping between IRQ0 ticks the server can process
/// both in a *single* stack poll — it then never observes
/// `Established` and, with the old `pump`, never re-listens (the
/// session-reset was gated on `netlog_streaming`). Every later
/// connection was refused → "0 bytes". The reading sessions prove the
/// normal history-then-tail stream works *after* those fast clients
/// came and went (session 2 is the reconnect the single-session
/// harness never covered).
///
/// Returns the total byte count across both reading sessions; a
/// detailed error naming the failing phase otherwise.
fn netlog_probe(container: &str) -> Result<usize, String> {
    // Fast connect + immediate close, no read: two rounds (if the
    // first wedges the listener, the second round's refused connect
    // is the error that reports it). Exit 11 = connect refused.
    for round in 1..=2 {
        let script = "exec 3<>/dev/tcp/127.0.0.1/2224 || exit 11; exec 3>&-";
        let out = Command::new("docker")
            .args(["exec", container, "bash", "-c", script])
            .output()
            .map_err(|e| format!("fast close {round}: cannot run docker exec: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(format!(
                "fast close {round}: connect failed (status: {}; stderr: {}) — the listener died after a previous client came and went",
                out.status,
                stderr.trim()
            ));
        }
        // Let the server's next poll (≤ one IRQ0 tick away) process
        // our FIN and re-listen before dialing again: without the
        // fix this sleep cannot help (nothing ever re-listens), with
        // it 500 ms is a 50× margin over the ~10 ms poll cadence.
        std::thread::sleep(Duration::from_millis(500));
    }
    let first = netlog_session(container, "session 1", 4)?;
    // Give the server one poll round to process our FIN and re-listen
    // before dialing again (a same-instant reconnect would race the
    // state machine rather than test it).
    std::thread::sleep(Duration::from_secs(1));
    let second = netlog_session(container, "session 2", 8)?;
    Ok(first + second)
}

/// Userland smoke: boots the dedicated ISO with the `hello` userland
/// module and asserts the hito-1 markers (ELF_OK, USER_RUN_OK,
/// SYSCALL_OK, USER_RETURN_OK) plus hito 2 (SCHED_RR_OK, USER_YIELD_OK,
/// USER_FAULT_OK) after the unchanged boot chain.
fn smoke_user(root: &Path) -> bool {
    let markers: Vec<&str> = vec![
        "BOOT_OK",
        "VGA_OK",
        "MEM_OK",
        "ALLOC_OK",
        "RTC_OK",
        "PCI_OK",
        "USB_KBD_OK",
        "E1000_OK",
        "NET_OK",
        "PING_OK",
        "DHCP_OK",
        "DNS_OK",
        "TCP_OK",
        "TLS_OK",
        "HTTP_OK",
        "GIT_LSREMOTE_OK",
        "GIT_FETCH_OK",
        "SSH_KEXINIT_OK",
        "SSH_KEX_OK",
        "INT_OK",
        "SHELL_OK",
        "ELF_OK",
        "USER_RUN_OK",
        "SYSCALL_OK",
        // Hito 3: the user process proves the VGA service round-trip and
        // serves its own prompt before handing control back to PID0.
        "USER_CONSOLE_OK",
        "USER_SHELL_OK",
        // Hito 4: the user process proves the FS syscalls (including the
        // fail-closed path/fd cases) and the gap-buffer save/byte-exact
        // read-back before handing control back to PID0.
        "USER_FS_OK",
        "USER_EDITOR_OK",
        // Hito 6: the parent process spawns a child from the same ELF,
        // waits for it, reads its echo back over the bounded IPC channel
        // and verifies the RAM-volume file before printing this marker.
        "USER_GIT_OK",
        "USER_RETURN_OK",
        "SCHED_RR_OK",
        "USER_YIELD_OK",
        "USER_FAULT_OK",
    ];
    if !iso_inner(root, false, true) {
        return false;
    }
    boot_assert(root, "smoke-user", &markers, SMOKE_TIMEOUT, &[], &[], true)
}

fn smoke(root: &Path) -> bool {
    const BASE_MARKERS: [&str; 30] = [
        "BOOT_OK",
        "VGA_OK",
        "MEM_OK",
        "ALLOC_OK",
        "RTC_OK",
        "PCI_OK",
        "USB_KBD_OK",
        "E1000_OK",
        "NET_OK",
        "PING_OK",
        "DHCP_OK",
        "DNS_OK",
        "TCP_OK",
        "TLS_OK",
        "HTTP_OK",
        "GIT_LSREMOTE_OK",
        "GIT_FETCH_OK",
        "SSH_KEXINIT_OK",
        "SSH_KEX_OK",
        "INT_OK",
        "TUI_OK",
        "EDITOR_OK",
        "AI_CHAT_OK",
        "BROWSER_FETCH_OK",
        "AI_EDIT_OK",
        "BROWSER_RENDER_OK",
        "BROWSER_CSS_OK",
        "BROWSER_NAV_OK",
        "SHELL_OK",
        "KEYBOARD_OK",
    ];
    // The U1 marker is only meaningful when the ISO actually carries the
    // `hello` module. Before `user/hello/` lands (or on a boot without it)
    // the chain stays exactly the original 30 markers.
    // The normal smoke never stages the hello module, so its marker
    // chain is the original 30 — byte-identical, no ELF_OK.
    let markers: Vec<&str> = BASE_MARKERS.to_vec();
    if !iso(root) {
        return false;
    }
    boot_assert(root, "smoke", &markers, SMOKE_TIMEOUT, &[], &[], true)
}

/// Installer milestones 1 + FS1 + FS2 + **I1** + **I2** (`BLK_OK`,
/// `FAT_OK`, `FS_WRITE_OK`, `INST_OK`, `NETINST_OK`) plus the AHCI
/// probe (`AHCI_OK`): build the ISO, then write **two** 64 MiB images
/// into `target/iso-root` (after `iso()` wiped it): `disk.img`, a valid
/// FAT16 *source* volume ([`write_disk_image`]), and `target.img`, a
/// blank disk carrying only the wipe-marker magic
/// ([`write_target_image`]). A **third** image, `disk-ahci.img`, is a
/// byte copy of the source volume and is attached through QEMU's AHCI
/// controller (`-device ich9-ahci,id=sata` + `-drive if=none` +
/// `-device ide-hd,bus=sata.1`) — the MacBook's ICH7 transport, which
/// the legacy PIO driver cannot reach; it is the additive `AHCI_OK`
/// proof (IDENTIFY + LBA0 read + magic) and does not change which disk
/// the FS/GPT/install proofs use.
///
/// Boot with the two IDE disks — source first (master, unit 0), target
/// second (slave, unit 1), the order `ata::probe`/`ata::probe_target`
/// enumerate — and require the kernel's `BLK_OK` (ATA probe accepted
/// LBA0), `AHCI_OK` (the AHCI controller found the same volume's copy
/// through IDENTIFY + LBA0), `FAT_OK` (mounted the
/// source volume, `/README.TXT` byte-exact), `FS_WRITE_OK` (wrote
/// `/RESULT.TXT`, re-mounted from scratch, read back with README
/// re-checked) and `INST_OK` (the full install flow on the *target*:
/// GPT written and re-read through `gptwire`, p2 formatted FAT16 with
/// the shared `fat::format_fat16`, payload copied from the source
/// volume, p2 re-mounted and read back byte-exact — see
/// `kernel/src/install.rs`), `GIT_STORE_OK` (G5's `.git` + local commit
/// proved from a fresh mount) and `GIT_PUSH_OK` (G6: the local commit's
/// graph encoded as a full-object pack, POSTed to the in-container
/// receive-pack mock, whose `unpack ok` / `ok refs/heads/main` report
/// the guest asserts), and `NETINST_OK` (I2: after the boot
/// network chain, the kernel fetches `payload.tar` (the built kernel
/// and README, served by the in-container responder on `10.0.2.2:8080`
/// from `payload-http.txt`, written by [`write_payload_mock`]) over
/// its own stack, walks the ustar headers, reinstalls onto the target
/// and reads every file back byte-exact).
///
/// After the VM passes, [`verify_pushed_pack`] proves the **upload**
/// on the host: the request bytes the mock captured are decoded with
/// `git-pack`, compared object-for-object against the `.git` on
/// `disk.img`, and finally handed to real `git index-pack
/// --strict`/`cat-file`/`ls-tree`. Then [`verify_installed_image`]
/// re-checks `target.img` **on the host** — docs/installer.md §7.3's
/// "assert after QEMU exits": GPT parsed independently of the running
/// kernel, layout checked, and the installed `/KERNEL.ELF` compared
/// byte-for-byte against the **built kernel binary** (ground truth on
/// the host — a corrupted download fails here even though the guest
/// verified its own copy).
///
/// Note both images are created **after** `iso()` (which wipes
/// `target/iso-root`) and live inside it, so the container's `/iso`
/// bind mount exposes them to QEMU at `/iso/<name>`.
fn smoke_install(root: &Path) -> bool {
    if !iso(root) {
        return false;
    }
    let disk = root.join("target/iso-root/disk.img");
    let target = root.join("target/iso-root/target.img");
    let ahci_disk = root.join("target/iso-root/disk-ahci.img");
    if let Err(e) = write_disk_image(&disk) {
        eprintln!("xtask: cannot create {}: {e}", disk.display());
        return false;
    }
    if let Err(e) = write_target_image(&target) {
        eprintln!("xtask: cannot create {}: {e}", target.display());
        return false;
    }
    // The same FAT16 source volume, byte for byte, attached through the
    // AHCI controller: the driver's IDENTIFY + LBA0 read must find the
    // magic the IDE disk carries (the additive `AHCI_OK` proof).
    if let Err(e) = std::fs::copy(&disk, &ahci_disk) {
        eprintln!(
            "xtask: cannot create {} from {}: {e}",
            ahci_disk.display(),
            disk.display()
        );
        return false;
    }
    let disks: [&Path; 2] = [&disk, &target];
    let ahci_disks: [&Path; 1] = [&ahci_disk];
    if !boot_assert(
        root,
        "smoke-install",
        &[
            "BLK_OK",
            "AHCI_OK",
            "FAT_OK",
            "FS_WRITE_OK",
            "FS_TREE_OK",
            "INST_OK",
            "GIT_CHECKOUT_OK",
            "GIT_STORE_OK",
            "GIT_PUSH_OK",
            "NETINST_OK",
        ],
        INSTALL_TIMEOUT,
        &disks,
        &ahci_disks,
        false,
    ) {
        return false;
    }
    // G6: the push's host-side proof — the pack the mock actually
    // received (captured by the in-container `nc`) is decoded and
    // compared against the `.git` on the source volume, then handed to
    // real host `git`. The guest already asserted the server's
    // `unpack ok` / `ok refs/heads/main` report (`GIT_PUSH_OK`).
    if !verify_pushed_pack(root, &disk) {
        return false;
    }
    if !verify_installed_image(&target) {
        return false;
    }
    // I1b: the decisive proof — boot the installed disk **alone**, with
    // no ISO attached, and require the installed kernel's boot chain.
    if !boot_assert_disk(
        root,
        "smoke-install-disk",
        &DISK_BOOT_MARKERS,
        DISK_BOOT_TIMEOUT,
        &target,
    ) {
        return false;
    }
    println!(
        "smoke-install: disk boot ok — target.img boots standalone through GRUB ({} + {} + … + {})",
        DISK_BOOT_MARKERS[0],
        DISK_BOOT_MARKERS[1],
        DISK_BOOT_MARKERS[DISK_BOOT_MARKERS.len() - 1]
    );
    true
}

/// S5 + the OpenSSH interop phase: the two-VM sshd proof
/// (`cargo xtask smoke-ssh`).
///
/// One container, two QEMUs started together:
///
/// - **VM1 (server)** boots with a FAT16 disk carrying `/HOST.BIN` (a
///   generated ed25519 host-key seed) and `/AUTH.KEY` (the *client*
///   key's `ssh-ed25519 <blob>` line). Its kernel starts the sshd on
///   guest :2222 and waits for connections — first VM2's own client,
///   then the interop phase below.
/// - **VM2 (client)** boots with a disk carrying `/CLIENT.BIN` (the
///   matching seed). After its normal boot chain it connects to
///   `10.0.2.2:2222` — slirp's gateway is the container's loopback,
///   where VM1's `-netdev user,...,hostfwd=tcp:0.0.0.0:2222-:2222`
///   listens — authenticates with `publickey`, execs
///   `echo SSHD_EXEC_OK` and prints `SSHD_OK` / `SSHD_EXEC_OK`.
/// - **Interop**: once VM2's chain passed, xtask `docker exec`s a
///   **real OpenSSH client** inside the same container (its loopback
///   is where :2222 is published) against the same sshd, as the
///   second connection of the same boot, and requires the exec output
///   `INTEROP_OK` — plus the kernel's `SSHD_INTEROP_OK` on VM1's
///   serial. This is the regression net for the live-hardware finding
///   (Debian's OpenSSH got `Permission denied (publickey)` against the
///   real MacBook while our own client passed; see
///   docs/git-ssh-deps.md §B).
///
/// VM1's serial goes to `target/iso-root/sshd-server-serial.log` (the
/// bind mount at `/iso`, so the host can read it); VM2's serial is the
/// container's stdout, drained exactly like `boot_assert`'s. Both VMs
/// die with the container (`docker rm -f`), on every exit path.
///
/// Keys are generated per run from **one** `ssh-keygen` invocation:
/// the OpenSSH private file `target/iso-root/interop_key` (the
/// interop client's `-i` key, never on any disk image the guest
/// reads), `/CLIENT.BIN`'s seed and `/AUTH.KEY`'s line all come from
/// that same key; VM1's host-key seed still comes from
/// `/dev/urandom`. None of it is printed or committed — only the
/// fingerprint the kernels log.
fn smoke_ssh(root: &Path) -> bool {
    if !iso(root) {
        return false;
    }
    let iso_dir = root.join("target/iso-root");
    let server_disk = iso_dir.join("sshd-server.img");
    let client_disk = iso_dir.join("sshd-client.img");

    let mut client_seed = [0u8; 32];
    let mut server_seed = [0u8; 32];
    let mut authorized = Vec::new();
    if let Err(e) = generate_ssh_smoke_keys(
        &iso_dir,
        &mut client_seed,
        &mut server_seed,
        &mut authorized,
    ) {
        eprintln!("xtask: smoke-ssh: cannot generate the keypair: {e}");
        return false;
    }

    let written = write_fat16_image(
        &server_disk,
        &[
            ("README.TXT", README_CONTENT),
            ("HOST.BIN", &server_seed[..]),
            ("AUTH.KEY", &authorized[..]),
        ],
    )
    .and_then(|()| {
        write_fat16_image(
            &client_disk,
            &[
                ("README.TXT", README_CONTENT),
                ("CLIENT.BIN", &client_seed[..]),
            ],
        )
    });
    // The seeds only ever needed to exist in those two images.
    client_seed.fill(0);
    server_seed.fill(0);
    if let Err(e) = written {
        eprintln!("xtask: smoke-ssh: cannot create the disk images: {e}");
        return false;
    }

    run_two_vm_ssh(root, &iso_dir, &server_disk, &client_disk)
}

/// The client VM's chain: its normal boot still resolves/fetches GitHub
/// (DNS_OK, SSH_KEX_OK), then the S5 leg prints SSHD_OK after auth and
/// SSHD_EXEC_OK after the exec output came back.
const SSH_CLIENT_MARKERS: [&str; 4] = ["DNS_OK", "SSH_KEX_OK", "SSHD_OK", "SSHD_EXEC_OK"];
/// The server VM's chain, asserted from its serial file: listen →
/// VM2's session → the **OpenSSH interop** session (`SSHD_INTEROP_OK`
/// is printed by the kernel after the second connection authenticated
/// and ran its exec — the interop client's own `INTEROP_OK` output is
/// asserted separately by [`run_openssh_interop`]).
const SSH_SERVER_MARKERS: [&str; 4] = [
    "SSHD_LISTEN_OK",
    "SSHD_KEXINIT_OK",
    "SSHD_SESSION_OK",
    "SSHD_INTEROP_OK",
];
/// Budget for the whole two-VM exchange (both boots + KEX + auth +
/// exec). The client's own boot chain (GitHub TLS/git/ssh) is the bulk.
const SSH_SMOKE_TIMEOUT: Duration = Duration::from_secs(90);
/// The OpenSSH interop phase's own budget: it starts only after VM2's
/// chain finished, and retries `ssh` while the server is still closing
/// session 1 / opening its second accept window.
const SSH_INTEROP_TIMEOUT: Duration = Duration::from_secs(60);
/// The per-run interop key file: host path `<iso>/interop_key`,
/// container path [`INTEROP_KEY_CONTAINER`] — one `ssh-keygen` keypair
/// shared by `/CLIENT.BIN`, `/AUTH.KEY` and this file.
const INTEROP_KEY_FILE: &str = "interop_key";
/// Where the tools container sees [`INTEROP_KEY_FILE`] (the bind mount
/// at `/iso`).
const INTEROP_KEY_CONTAINER: &str = "/iso/interop_key";
/// The exec command the interop client runs — its echoed output is the
/// assertion token.
const INTEROP_COMMAND: &str = "echo INTEROP_OK";
/// The token the remote `echo` must produce back on the client's
/// stdout.
const INTEROP_TOKEN: &str = "INTEROP_OK";

/// One ed25519 keypair for the harness, from **one** `ssh-keygen`
/// invocation: the OpenSSH private-key file (`<iso>/interop_key`,
/// read by the real `ssh` of the interop phase), VM2's `/CLIENT.BIN`
/// seed, and the `/AUTH.KEY` line VM1 compares against all carry the
/// same key; only VM1's host-key seed still comes from
/// `/dev/urandom`. `ed25519-dalek` is xtask-only (review in
/// `xtask/Cargo.toml`).
///
/// The OpenSSH file is parsed here (not converted with another tool)
/// because its `openssh-key-v1` private section is exactly the module
/// layout of `keyfile::module_config`: a 64-byte block of
/// `seed ‖ pub`. Three independent checks must agree before anything
/// is written — the file's own public half, the seed's
/// `ed25519-dalek` derivation, and the `.pub` line ssh-keygen wrote —
/// so a parser bug fails loudly at generation time instead of looking
/// like an auth failure later.
fn generate_ssh_smoke_keys(
    iso_dir: &Path,
    client_seed: &mut [u8; 32],
    server_seed: &mut [u8; 32],
    authorized: &mut Vec<u8>,
) -> std::io::Result<()> {
    use ed25519_dalek::SigningKey;
    use std::io::{Error, Read};

    let key_path = iso_dir.join(INTEROP_KEY_FILE);
    let pub_path = format!("{}.pub", key_path.display());
    // ssh-keygen refuses to overwrite; the previous run's key is
    // dead the moment this one exists.
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&pub_path);
    let status = Command::new("ssh-keygen")
        .args([
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-C",
            "reemplazo-smoke",
            "-f",
        ])
        .arg(&key_path)
        .status()?;
    if !status.success() {
        return Err(Error::other("ssh-keygen could not write the interop key"));
    }

    let (seed, public) = parse_openssh_ed25519(&std::fs::read(&key_path)?)?;

    // Cross-check 1: the seed must derive the public key it ships
    // with (this is the same math the kernel client and sshd do).
    if SigningKey::from_bytes(&seed).verifying_key().to_bytes() != public {
        return Err(Error::other(
            "interop key: seed does not derive the bundled public key",
        ));
    }
    // Cross-check 2: the `.pub` line must carry the same key blob.
    let pub_text = std::fs::read_to_string(&pub_path)?;
    let mut parts = pub_text.split_whitespace();
    let (alg, b64) = match (parts.next(), parts.next()) {
        (Some(alg), Some(b64)) => (alg, b64),
        _ => return Err(Error::other("interop key: malformed .pub line")),
    };
    if alg != "ssh-ed25519" {
        return Err(Error::other("interop key: .pub line is not ssh-ed25519"));
    }
    let mut blob = [0u8; ssh_wire::ED25519_KEY_BLOB_LEN];
    let m = ssh_wire::base64_decode(b64.as_bytes(), &mut blob)
        .ok_or_else(|| Error::other("interop key: .pub line is not base64"))?;
    let from_pub_line =
        ssh_wire::parse_ed25519_key_blob(&blob[..m]).map_err(|_| Error::other("interop key"))?;
    if from_pub_line != public {
        return Err(Error::other(
            "interop key: .pub line and private key disagree",
        ));
    }

    client_seed.copy_from_slice(&seed);

    let mut bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    server_seed.copy_from_slice(&bytes);
    bytes.fill(0);

    // The authorized-keys line from the same public half.
    let n = ssh_wire::ed25519_key_blob(&public, &mut blob)
        .ok_or_else(|| Error::other("key blob does not fit"))?;
    let mut b64 = [0u8; 96];
    let m = ssh_wire::base64_encode(&blob[..n], true, &mut b64)
        .ok_or_else(|| Error::other("base64 does not fit"))?;
    authorized.clear();
    authorized.extend_from_slice(b"ssh-ed25519 ");
    authorized.extend_from_slice(&b64[..m]);
    authorized.extend_from_slice(b" reemplazo-smoke\n");
    Ok(())
}

/// Parse an unencrypted `openssh-key-v1` ed25519 private key (what
/// `ssh-keygen -t ed25519 -N ''` writes) into `(seed, public)`.
///
/// Layout (PROTOCOL.key + sshkey.c, verified against a live
/// ssh-keygen file): magic, `ciphername = none`, `kdfname = none`,
/// empty KDF options, `nkeys = 1`, the public section
/// `string "ssh-ed25519" ‖ string <32>`, then the private section:
/// two equal `checkint` words, `string "ssh-ed25519"`, `string <32>`
/// (the public key again), `string <64>` (`seed ‖ pub`), the comment
/// string, and `1,2,3,…` padding to an 8-byte boundary. Fail-closed:
/// every one of those is checked, trailing bytes are refused, and the
/// key bytes themselves never reach an error message.
fn parse_openssh_ed25519(file: &[u8]) -> std::io::Result<([u8; 32], [u8; 32])> {
    use std::io::{Error, ErrorKind};

    fn bad(msg: &'static str) -> Error {
        Error::new(ErrorKind::InvalidData, msg)
    }
    fn take<'a>(buf: &'a [u8], at: &mut usize, n: usize) -> std::io::Result<&'a [u8]> {
        let end = at
            .checked_add(n)
            .ok_or_else(|| bad("key offset overflow"))?;
        let slice = buf.get(*at..end).ok_or_else(|| bad("key file truncated"))?;
        *at = end;
        Ok(slice)
    }
    fn word(buf: &[u8], at: &mut usize) -> std::io::Result<u32> {
        let s = take(buf, at, 4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn field<'a>(buf: &'a [u8], at: &mut usize) -> std::io::Result<&'a [u8]> {
        let n = usize::try_from(word(buf, at)?).map_err(|_| bad("key field length"))?;
        take(buf, at, n)
    }

    // The PEM armor: take the base64 between the BEGIN/END lines and
    // drop interior whitespace (the strict decoder allows it only at
    // the ends).
    let text = std::str::from_utf8(file).map_err(|_| bad("key file is not PEM text"))?;
    let begin = "-----BEGIN OPENSSH PRIVATE KEY-----";
    let end = "-----END OPENSSH PRIVATE KEY-----";
    let body = text
        .split_once(begin)
        .and_then(|(_, rest)| rest.split_once(end))
        .map(|(body, _)| body)
        .ok_or_else(|| bad("key file has no OPENSSH PRIVATE KEY armor"))?;
    let mut b64 = String::with_capacity(body.len());
    for c in body.chars() {
        if !c.is_whitespace() {
            b64.push(c);
        }
    }
    let mut raw = [0u8; 512];
    let n = ssh_wire::base64_decode(b64.as_bytes(), &mut raw)
        .ok_or_else(|| bad("key body is not base64"))?;
    let key = &raw[..n];

    const MAGIC: &[u8] = b"openssh-key-v1\0";
    let mut at = 0usize;
    if take(key, &mut at, MAGIC.len())? != MAGIC {
        return Err(bad("key body is not openssh-key-v1"));
    }
    if field(key, &mut at)? != b"none" {
        return Err(bad("interop key is encrypted (want none cipher)"));
    }
    if field(key, &mut at)? != b"none" {
        return Err(bad("interop key uses a KDF (want none)"));
    }
    let _kdf_options = field(key, &mut at)?;
    if word(key, &mut at)? != 1 {
        return Err(bad("interop key must hold exactly one key"));
    }

    // The public section: `string "ssh-ed25519" ‖ string <32>`.
    let public_section = field(key, &mut at)?;
    let public = ssh_wire::parse_ed25519_key_blob(public_section)
        .map_err(|_| bad("interop key public section is malformed"))?;

    // The private section.
    let priv_section = field(key, &mut at)?;
    let mut p = 0usize;
    let check1 = word(priv_section, &mut p)?;
    let check2 = word(priv_section, &mut p)?;
    if check1 != check2 {
        return Err(bad("interop key checkints differ (corrupt key)"));
    }
    if field(priv_section, &mut p)? != b"ssh-ed25519" {
        return Err(bad("interop key private section is not ed25519"));
    }
    let section_public = field(priv_section, &mut p)?;
    if section_public != public {
        return Err(bad("interop key public halves disagree"));
    }
    let block = field(priv_section, &mut p)?;
    let block: [u8; 64] = block
        .try_into()
        .map_err(|_| bad("private block is not 64 bytes"))?;
    let _comment = field(priv_section, &mut p)?;
    // Trailing padding: 1,2,3,… to the 8-byte boundary.
    let mut pad = 1u8;
    while p < priv_section.len() {
        if priv_section[p] != pad {
            return Err(bad("interop key padding is wrong"));
        }
        pad = pad.wrapping_add(1);
        p += 1;
    }
    if at != key.len() {
        return Err(bad("trailing bytes after the openssh key"));
    }

    // `seed ‖ pub` — the same split `keyfile::module_config` makes of
    // the hardware `sshd` module.
    let seed: [u8; 32] = block[..32]
        .try_into()
        .map_err(|_| bad("seed half is not 32 bytes"))?;
    let block_public: [u8; 32] = block[32..]
        .try_into()
        .map_err(|_| bad("public half is not 32 bytes"))?;
    if block_public != public {
        return Err(bad("private block's public half disagrees"));
    }
    Ok((seed, public))
}

/// Build and run the two QEMUs in one container; assert the client's
/// markers on stdout and the server's on its serial file. Every exit
/// path kills the container (the orphan discipline).
fn run_two_vm_ssh(root: &Path, iso_dir: &Path, server_disk: &Path, client_disk: &Path) -> bool {
    if host_qemu() {
        // Two VMs need a shared `hostfwd` on :2222; the documented
        // backend for the smokes is the tools container (AGENTS.md).
        eprintln!(
            "xtask: smoke-ssh runs the two VMs inside {TOOLS_IMAGE}; \
             the host-QEMU backend is not supported for this mode"
        );
        return false;
    }
    if let Err(e) = write_chat_mock(iso_dir) {
        eprintln!("xtask: smoke-ssh: cannot write the chat mock: {e}");
        return false;
    }
    if let Err(e) = write_push_mock(iso_dir) {
        eprintln!("xtask: smoke-ssh: cannot write the push mock: {e}");
        return false;
    }
    let _ = std::fs::remove_file(iso_dir.join("push-capture.bin"));
    let container = vm_container(root, "smoke-ssh");
    rm_container(&container); // stale VM from a killed session
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return false;
    }

    let server_log = iso_dir.join("sshd-server-serial.log");
    let _ = std::fs::remove_file(&server_log);

    let server_name = match server_disk.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return false,
    };
    let client_name = match client_disk.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => return false,
    };

    // VM1: serial to the bind-mounted iso dir, guest :2222 published on
    // the container's loopback (VM2's slirp gateway).
    let mut server_args = qemu_std_args_ex(
        "/iso/os.iso",
        &format!("tcp:0.0.0.0:{},server,nowait", monitor_port_n(root, 1)),
        "file:/iso/sshd-server-serial.log",
        Some(("0.0.0.0", 2222, 2222)),
    );
    server_args.push("-drive".into());
    server_args.push(format!("file=/iso/{server_name},if=ide,format=raw"));

    // VM2: serial on the container's stdout (the markers xtask reads).
    let mut client_args = qemu_std_args_ex(
        "/iso/os.iso",
        &format!("tcp:127.0.0.1:{},server,nowait", monitor_port(root)),
        "stdio",
        None,
    );
    client_args.push("-drive".into());
    client_args.push(format!("file=/iso/{client_name},if=ide,format=raw"));

    let server_cmd = format!("qemu-system-x86_64 {}", join_shell_args(&server_args));
    let script = format!(
        "{} {} >/dev/null 2>&1 & exec qemu-system-x86_64 \"$@\"",
        mock_loop_prefix(),
        server_cmd
    );

    let mut docker_args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--name".into(),
        container.clone(),
        "-v".into(),
        format!("{}:/iso", iso_dir.display()),
        TOOLS_IMAGE.into(),
        "sh".into(),
        "-c".into(),
        script,
        "qemu-system-x86_64".into(),
    ];
    docker_args.extend(client_args.iter().cloned());

    let mut child = match Command::new("docker")
        .args(&docker_args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            eprintln!("xtask: smoke-ssh: cannot start docker: {e}");
            rm_container(&container);
            return false;
        }
    };
    let rx = spawn_line_reader(&mut child);

    let mut next_marker = 0usize;
    let mut collected: Vec<String> = Vec::new();
    let client_ok = wait_for_markers(
        &rx,
        &SSH_CLIENT_MARKERS,
        &mut next_marker,
        &mut collected,
        SSH_CLIENT_MARKERS.len(),
        Instant::now() + SSH_SMOKE_TIMEOUT,
        false,
    );

    // OpenSSH interop phase — while the container (and VM1's sshd,
    // now opening its second accept window) is still alive. The real
    // `ssh` runs *inside* the container: guest :2222 is published on
    // that network namespace's loopback, which the host cannot reach,
    // so `docker exec` is the clean way in (no sidecar needed).
    let interop_ok = if client_ok {
        run_openssh_interop(&container, "2222")
    } else {
        eprintln!("smoke-ssh: interop skipped (the client VM's chain failed first)");
        false
    };
    if interop_ok {
        // The kernel prints SSHD_INTEROP_OK only after the interop
        // session completed; get it into the bind-mounted serial file
        // before the container is killed.
        let _ = wait_for_file_markers(
            &server_log,
            &["SSHD_INTEROP_OK"],
            Instant::now() + Duration::from_secs(5),
        );
    }

    let mut no_mock = None;
    stop_vm(&mut child, Some(&container), &mut no_mock);

    // The server's serial is a host-visible file (bind mount). Its last
    // marker may still be in flight when the client finishes, so poll
    // briefly before judging.
    let server_ok = wait_for_file_markers(
        &server_log,
        &SSH_SERVER_MARKERS,
        Instant::now() + Duration::from_secs(5),
    );

    if client_ok && interop_ok && server_ok {
        println!(
            "smoke-ssh: PASS — client {}; server {}; interop OpenSSH echoed {INTEROP_TOKEN}",
            SSH_CLIENT_MARKERS.join(" + "),
            SSH_SERVER_MARKERS.join(" + ")
        );
        true
    } else {
        if !client_ok {
            let missing = SSH_CLIENT_MARKERS[next_marker..].join(" + ");
            eprintln!("smoke-ssh: FAIL — client missing {missing} within {SSH_SMOKE_TIMEOUT:?}");
        }
        if client_ok && !interop_ok {
            eprintln!(
                "smoke-ssh: FAIL — OpenSSH interop phase failed within {SSH_INTEROP_TIMEOUT:?} \
                 (server verdicts are in the serial dump below)"
            );
        }
        if !server_ok {
            eprintln!(
                "smoke-ssh: FAIL — server did not print {} in order",
                SSH_SERVER_MARKERS.join(" + ")
            );
        }
        for line in &collected {
            eprintln!("smoke-ssh| {line}");
        }
        if let Ok(log) = std::fs::read_to_string(&server_log) {
            for line in log.lines() {
                eprintln!("smoke-ssh|srv| {line}");
            }
        }
        false
    }
}

/// The OpenSSH interop phase of `smoke-ssh`: run a **real** OpenSSH
/// client (the tools container's `ssh`, Debian's own package) against
/// VM1's sshd as its *second* connection, and require the exec output
/// to come back.
///
/// Why `docker exec`: VM1's `-netdev user,...,hostfwd=tcp:0.0.0.0:2222`
/// publishes guest :2222 on the **container's** loopback (that is
/// where VM2's slirp gateway leads too), and on Docker Desktop the
/// container's loopback is not reachable from the host — so the
/// client must run inside that network namespace. The container is
/// still alive here (`stop_vm` comes later), so a plain `docker exec`
/// is the whole story; no sidecar container is needed.
///
/// Retry policy: `ssh` exits for two very different reasons.
/// Connection-level failures (`refused`/`timed out` — the server is
/// still closing session 1 or opening its second accept window) are
/// retried until [`SSH_INTEROP_TIMEOUT`]; an **auth verdict** —
/// `Permission denied` after a full handshake — is definitive and
/// ends the loop at once, so the exact failure the real MacBook hit
/// is reported verbatim instead of being masked by later retries.
/// Every attempt's output is echoed into the harness log either way.
fn run_openssh_interop(container: &str, port: &str) -> bool {
    // Belt and braces: bind-mounted files can surface with loose
    // modes on some Docker Desktop filesystems, and ssh refuses a
    // private key that is not its owner's to read only.
    let _ = Command::new("docker")
        .args(["exec", container, "chmod", "600", INTEROP_KEY_CONTAINER])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let ssh_args = [
        "exec",
        // The macOS client sends `env LANG=…` before `exec` (its
        // ssh_config has `SendEnv LANG LC_*`); the container shipped
        // without LANG, so the env request never happened here and a
        // server that drops on it (the `TrailingGarbage` bug behind
        // the live-hardware exec failure) passed QEMU. Setting LANG
        // makes this harness exercise the same request path as the
        // real machine.
        "-e",
        "LANG=en_US.UTF-8",
        container,
        "ssh",
        "-i",
        INTEROP_KEY_CONTAINER,
        "-p",
        port,
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "ConnectTimeout=3",
        "reemplazo@127.0.0.1",
        INTEROP_COMMAND,
    ];
    let deadline = Instant::now() + SSH_INTEROP_TIMEOUT;
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let out = Command::new("docker").args(ssh_args).output();
        match out {
            Ok(o) => {
                let mut text = String::from_utf8_lossy(&o.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&o.stderr));
                for line in text.lines() {
                    println!("smoke-ssh|interop| {line}");
                }
                if o.status.success() && text.contains(INTEROP_TOKEN) {
                    println!(
                        "smoke-ssh|interop: PASS — real OpenSSH authenticated (attempt {attempt})"
                    );
                    return true;
                }
                // A full handshake that ends in `Permission denied` is
                // the server's verdict on the auth path itself — no
                // retry can change it, and retrying would bury it.
                if text.contains("Permission denied") {
                    eprintln!("smoke-ssh: FAIL — OpenSSH got a publickey verdict from the sshd");
                    return false;
                }
            }
            Err(e) => {
                eprintln!("smoke-ssh: cannot run the interop ssh in {container}: {e}");
                return false;
            }
        }
        if Instant::now() >= deadline {
            eprintln!(
                "smoke-ssh: FAIL — OpenSSH interop gave up after {attempt} attempts \
                 within {SSH_INTEROP_TIMEOUT:?} (last output above)"
            );
            return false;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The A3/A5 chat mock without the `exec` tail: the two-VM script needs
/// it in the background beside the server VM (same five connections
/// per port, same `/iso` response files — VM2 is the only VM that
/// posts; `:8098` keeps the A4 SSE proof alive on both VMs). The G6
/// push mock rides along: two VMs, each with a disk, each pushes.
fn mock_loop_prefix() -> String {
    format!(
        "{}for i in 1 2 3 4 5; do \
         nc -l -s 127.0.0.1 -p 8099 < /iso/chat-mock-response.txt > /dev/null 2>&1 || true; \
         done & \
         for i in 1 2 3 4 5; do \
         nc -l -s 127.0.0.1 -p 8098 < /iso/chat-mock-sse-response.txt > /dev/null 2>&1 || true; \
         done &",
        push_mock_loop()
    )
}

/// Join already-space-free QEMU arguments into one `sh -c` word list.
/// Every argument this harness builds is a path/flag with no spaces
/// (asserted), so a plain join is exact — no shell quoting ambiguity.
fn join_shell_args(args: &[String]) -> String {
    debug_assert!(
        args.iter().all(|a| !a.contains(char::is_whitespace)),
        "qemu args must be space-free for the two-VM shell command"
    );
    args.join(" ")
}

/// Drain a child's stdout+stderr into a line channel (the same reader
/// `boot_assert` uses).
fn spawn_line_reader(child: &mut Child) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel::<String>();
    let mut pipes: Vec<Box<dyn std::io::Read + Send>> = Vec::new();
    if let Some(out) = child.stdout.take() {
        pipes.push(Box::new(out));
    }
    if let Some(err) = child.stderr.take() {
        pipes.push(Box::new(err));
    }
    for pipe in pipes {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
    }
    drop(tx);
    rx
}

/// Read `path` until every marker appears in order (or the deadline
/// passes). Used for the background server VM's serial file.
fn wait_for_file_markers(path: &Path, markers: &[&str], deadline: Instant) -> bool {
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            let mut next = 0usize;
            for line in text.lines() {
                if next < markers.len() && line.contains(markers[next]) {
                    next += 1;
                }
            }
            if next == markers.len() {
                return true;
            }
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Fixed installer-smoke disk size: 64 MiB is plenty for the installer
/// milestones (payload ≈1 MB) and cheap to (re)create every run — and
/// both images share it, so source and target differ only in content.
const DISK_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Magic pattern at LBA0 of the installer smoke's *source* disk —
/// byte-identical to `MAGIC` in `kernel/src/ata.rs` (xtask cannot
/// depend on the `no_std` kernel crate, so the bytes are duplicated
/// here).
const DISK_MAGIC: &[u8] = b"reemplazo-disk-v1";

/// Magic pattern at LBA0 of the *target* disk (the blank image the
/// installer is allowed to wipe) — byte-identical to `TARGET_MAGIC` in
/// `kernel/src/ata.rs`. Deliberately different from [`DISK_MAGIC`]:
/// the kernel must never confuse source and target, and a second disk
/// **without** this marker is ignored by the installer (fail-closed —
/// see `kernel/src/install.rs`).
const TARGET_DISK_MAGIC: &[u8] = b"reemplazo-target-v1";

/// Byte offset of both probe magics inside LBA0 — byte-identical to
/// `MAGIC_OFFSET` in `kernel/src/ata.rs`. On the source, LBA0 is a
/// real FAT boot sector (0..3 jump, 3..10 OEM, 11..62 BPB, 510..512
/// `55 AA`), so the magic lives in the bootstrap area FAT never
/// parses; on the target, LBA0 is otherwise all zeros (no BPB, no
/// `55 AA` — never bootable).
const DISK_MAGIC_OFFSET: usize = 62;

/// Wrapping-sum checksum byte that follows each magic — duplicated
/// from `kernel/src/ata.rs`'s `magic_checksum` /
/// `target_magic_checksum`.
fn wrapping_sum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

/// Checksum after [`DISK_MAGIC`] (the source image's probe contract).
fn magic_checksum() -> u8 {
    wrapping_sum(DISK_MAGIC)
}

/// `/README.TXT`'s content — byte-identical to `README_EXPECTED` in
/// `kernel/src/fs/mod.rs` (host crates cannot depend on the kernel).
const README_CONTENT: &[u8] = b"reemplazo filesystem ok\n";

/// Fixed timestamp for `/README.TXT` (host-side, no RTC — a build
/// artifact stays byte-reproducible). Fields are FAT's own
/// (`fat::Stamp`, 1980..=2107 range).
const SOURCE_STAMP: fat::Stamp = fat::Stamp {
    year: 2026,
    month: 11,
    day: 21,
    hour: 0,
    minute: 0,
    second: 0,
};

// --- The installer layout, duplicated from `kernel/src/install.rs` ------
// (xtask cannot depend on the kernel; the GPT *types* come from the
// shared `gptwire` crate, only the numeric layout is re-stated here —
// the same duplication pattern as the probe magics above, and this
// test is exactly what catches the two sides drifting apart.)
const P1_FIRST_LBA: u64 = 2048; // bios_grub: 1 MiB @ 1 MiB (§3.2)
const P1_LAST_LBA: u64 = 4095;
const P2_FIRST_LBA: u64 = 4096; // data partition: rest of the disk

/// Create a 64 MiB raw disk image that is a valid **FAT16 volume**
/// (superfloppy layout: no partition table, the whole disk is the
/// volume) containing `/README.TXT`, with [`DISK_MAGIC`] + its checksum
/// at [`DISK_MAGIC_OFFSET`] in the boot sector — exactly the two-sided
/// contract `ata::probe` and `kernel/src/fs::prove` validate.
///
/// Formatting goes through `fat::format_fat16` — **the same
/// formatter the kernel's installer writes p2 with** (extracted from
/// this file in the I1 milestone; see `fat/src/format.rs`'s docs), so
/// this image is host-verified through the same reader/writer the
/// boot proof runs, before any VM starts. The image is built in
/// memory and written once; everything not explicitly written stays
/// zero.
fn write_disk_image(path: &Path) -> std::io::Result<()> {
    let img = MemImage::new(DISK_IMAGE_BYTES as usize);
    fat::format_fat16(
        &img,
        &fat::FormatOpts {
            label: b"REEMPLAZO  ",
            volume_id: 0x2026_1121,
            hidden_sectors: 0,
            // 4 KiB clusters: the source volume must hold the full
            // depth-1 git checkout (~114 files in 53 dirs; kernel/src
            // alone exceeds a 2 KiB-cluster directory's 32 entries and
            // `fat` does not grow directories — FS3 measured the
            // 4 KiB geometry as the fastest linear-first-fit size
            // that fits the tree).
            min_sectors_per_cluster: 8,
        },
    )
    .map_err(|e| std::io::Error::other(format!("fat::format_fat16: {e:?}")))?;

    // Probe magic in the boot sector's bootstrap area (the formatter
    // leaves 62.. zeroed; contract with `kernel/src/ata.rs`).
    let end = DISK_MAGIC_OFFSET + DISK_MAGIC.len();
    {
        let mut data = img.0.borrow_mut();
        data[DISK_MAGIC_OFFSET..end].copy_from_slice(DISK_MAGIC);
        data[end] = magic_checksum();
    }

    // `/README.TXT` through the crate's own writer — the formatter's
    // self-mount already proved the volume; this adds the file the
    // FS1 proof reads.
    {
        let fs = fat::Fat16::mount(&img)
            .map_err(|e| std::io::Error::other(format!("fat::mount: {e:?}")))?;
        fs.write_file("/README.TXT", README_CONTENT, SOURCE_STAMP)
            .map_err(|e| std::io::Error::other(format!("fat::write_file: {e:?}")))?;
    }
    std::fs::write(path, &*img.0.borrow())
}

// --- FAT16 geometry of the smoke disk ------------------------------------
//
// Fixed on purpose: `write_disk_image` writes these regions
// back-to-back (boot, FAT0, FAT1, root, data), and the kernel's
// `fs::prove` re-derives every offset from the BPB it reads back — so
// the two sides are a contract, not a coincidence. `FAT_CLUSTERS` is
// never written to the disk (FAT16 has no cluster-count field); the
// const asserts below pin the invariants the reader enforces.
const SECTOR_SIZE: usize = 512;
const FAT_RESERVED: u32 = 1;
const FAT_COUNT: u32 = 2;
const FAT_SECTORS: u32 = 64;
const FAT_ROOT_ENTRIES: u32 = 512;
const FAT_ROOT_SECTORS: u32 = FAT_ROOT_ENTRIES * 32 / SECTOR_SIZE as u32;
const FAT_SPC: u32 = 8; // sectors/cluster → 4 KiB clusters
const FAT_TOTAL_SECTORS: u32 = (DISK_IMAGE_BYTES / SECTOR_SIZE as u64) as u32;
const FAT_DATA_START: u32 = FAT_RESERVED + FAT_COUNT * FAT_SECTORS + FAT_ROOT_SECTORS;
const FAT_CLUSTERS: u32 = (FAT_TOTAL_SECTORS - FAT_DATA_START) / FAT_SPC;

/// The reader refuses volumes outside the FAT16 cluster window, and the
/// FAT must physically fit its reserved sectors — a geometry change
/// that breaks either fails the *build*, not a 40 s QEMU run.
const _: () = assert!(FAT_CLUSTERS >= 4085 && FAT_CLUSTERS <= 65524);
const _: () = assert!(FAT_CLUSTERS + 2 <= FAT_SECTORS * (SECTOR_SIZE as u32 / 2));

/// Cluster `/README.TXT` starts in (first data cluster).
const README_CLUSTER: u32 = 2;

fn write_fat16_image(path: &Path, files: &[(&str, &[u8])]) -> std::io::Result<()> {
    use std::io::ErrorKind;
    if files.len() > FAT_ROOT_ENTRIES as usize {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            "too many root entries for the fixed FAT16 root",
        ));
    }
    let cluster_bytes = FAT_SPC as usize * SECTOR_SIZE;
    let mut f = std::fs::File::create(path)?;
    f.set_len(DISK_IMAGE_BYTES)?; // sparse zeros first; the prefix is written below

    // Boot sector: a spec-shaped BPB (every field `fat::Fat16::mount`
    // validates is set here), magic in the bootstrap area.
    let mut boot = [0u8; SECTOR_SIZE];
    boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]); // jump over the BPB
    boot[3..11].copy_from_slice(b"MSDOS5.0"); // OEM name
    boot[11..13].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    boot[13] = FAT_SPC as u8;
    boot[14..16].copy_from_slice(&(FAT_RESERVED as u16).to_le_bytes());
    boot[16] = FAT_COUNT as u8;
    boot[17..19].copy_from_slice(&(FAT_ROOT_ENTRIES as u16).to_le_bytes());
    // total16 (19..21) stays 0: 131072 sectors needs the 32-bit field.
    boot[21] = 0xF8; // media descriptor (fixed disk)
    boot[22..24].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
    boot[24..26].copy_from_slice(&63u16.to_le_bytes()); // sectors/track
    boot[26..28].copy_from_slice(&255u16.to_le_bytes()); // heads
    // hidden (28..32) stays 0: the volume starts at LBA0.
    boot[32..36].copy_from_slice(&FAT_TOTAL_SECTORS.to_le_bytes());
    boot[36] = 0x80; // drive number
    boot[38] = 0x29; // extended boot signature → next three fields valid
    boot[39..43].copy_from_slice(&0x2026_1121u32.to_le_bytes()); // volume id
    boot[43..54].copy_from_slice(b"REEMPLAZO  ");
    boot[54..62].copy_from_slice(b"FAT16   ");
    boot[DISK_MAGIC_OFFSET..DISK_MAGIC_OFFSET + DISK_MAGIC.len()].copy_from_slice(DISK_MAGIC);
    boot[DISK_MAGIC_OFFSET + DISK_MAGIC.len()] = magic_checksum();
    boot[510] = 0x55; // signature: the last thing `mount` checks
    boot[511] = 0xAA;
    f.write_all(&boot)?;

    // Two identical FATs: media/end-of-chain bookkeeping plus one
    // contiguous chain per file, in allocation order from cluster 2.
    let mut fat = vec![0u8; FAT_SECTORS as usize * SECTOR_SIZE];
    fat[0..2].copy_from_slice(&0xFFF8u16.to_le_bytes()); // cluster 0: media
    fat[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes()); // cluster 1: reserved

    let mut root = vec![0u8; FAT_ROOT_SECTORS as usize * SECTOR_SIZE];
    let mut data: Vec<u8> = Vec::new();
    let mut next_cluster = README_CLUSTER;
    for (i, (name, content)) in files.iter().enumerate() {
        let (base, ext) = split_8_3(name)?;
        let clusters = content.len().max(1).div_ceil(cluster_bytes);
        let last = next_cluster as usize + clusters;
        if last > FAT_CLUSTERS as usize + 2 {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "files do not fit the FAT16 data region",
            ));
        }
        for c in 0..clusters {
            let cluster = next_cluster + c as u32;
            let value = if c + 1 == clusters {
                0xFFFFu16 // end of chain
            } else {
                (cluster + 1) as u16
            };
            let at = cluster as usize * 2;
            fat[at..at + 2].copy_from_slice(&value.to_le_bytes());
        }
        let entry = &mut root[i * 32..i * 32 + 32];
        entry[0..8].copy_from_slice(&base);
        entry[8..11].copy_from_slice(&ext);
        entry[11] = 0x20; // archive
        entry[26..28].copy_from_slice(&(next_cluster as u16).to_le_bytes());
        entry[28..32].copy_from_slice(&(content.len() as u32).to_le_bytes());

        data.extend_from_slice(content);
        data.resize(data.len() + clusters * cluster_bytes - content.len(), 0);
        next_cluster += clusters as u32;
    }
    f.write_all(&fat)?;
    f.write_all(&fat)?;
    f.write_all(&root)?;
    f.write_all(&data)?;
    f.sync_all()?;
    Ok(())
}

/// `"NAME.EXT"` → the fixed 8+3 bytes a FAT root entry holds (upper
/// case, space padded). Anything else is refused: this writer never
/// invents an LFN entry.
fn split_8_3(name: &str) -> std::io::Result<([u8; 8], [u8; 3])> {
    use std::io::ErrorKind;
    let (base, ext) = match name.split_once('.') {
        Some((base, ext)) => (base, ext),
        None => (name, ""),
    };
    if base.is_empty()
        || base.len() > 8
        || ext.len() > 3
        || base.contains('.')
        || !base.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        || !ext.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidInput,
            format!("{name} is not 8.3-encodable"),
        ));
    }
    let mut out_base = [b' '; 8];
    let mut out_ext = [b' '; 3];
    for (slot, byte) in out_base.iter_mut().zip(base.bytes()) {
        *slot = byte.to_ascii_uppercase();
    }
    for (slot, byte) in out_ext.iter_mut().zip(ext.bytes()) {
        *slot = byte.to_ascii_uppercase();
    }
    Ok((out_base, out_ext))
}

/// Create the 64 MiB **blank target** image: all zeros except the
/// wipe-marker [`TARGET_DISK_MAGIC`] + checksum at LBA0's bootstrap
/// area — no BPB, no `55 AA`, so it is never bootable, and it is
/// clearly *not* the source disk. The kernel's `ata::probe_target`
/// requires exactly this marker before the installer touches a disk
/// (fail-closed: an unmarked second disk is ignored, never wiped).
fn write_target_image(path: &Path) -> std::io::Result<()> {
    let mut img = vec![0u8; DISK_IMAGE_BYTES as usize];
    let end = DISK_MAGIC_OFFSET + TARGET_DISK_MAGIC.len();
    img[DISK_MAGIC_OFFSET..end].copy_from_slice(TARGET_DISK_MAGIC);
    img[end] = wrapping_sum(TARGET_DISK_MAGIC);
    std::fs::write(path, img)
}

/// In-memory disk image behind both block traits the repo's disk
/// crates speak — `fat::BlockDevice` (format/mount/copy/verify) and
/// `gptwire::Device` (GPT parse) — so every host-side check runs
/// through the same code paths the kernel runs, over plain bytes.
/// Interior mutability (`RefCell`) because both traits take `&self`
/// for writes (the kernel's adapter writes hardware through `&self`
/// too — same shape). Writes are plain bounds-checked copies.
struct MemImage(RefCell<Vec<u8>>);

impl MemImage {
    fn new(len: usize) -> Self {
        Self(RefCell::new(vec![0u8; len]))
    }

    fn from_vec(data: Vec<u8>) -> Self {
        Self(RefCell::new(data))
    }

    fn len(&self) -> u64 {
        self.0.borrow().len() as u64
    }

    /// Copy `[offset, offset+len)` out of the image, `None` when the
    /// range is outside it (the bounds stay checked here, like every
    /// block adapter's).
    fn range(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        let data = self.0.borrow();
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(len)?;
        data.get(start..end).map(<[u8]>::to_vec)
    }
}

/// The one range check both adapters share: aligned whole sectors,
/// non-empty, inside `size`.
fn sector_range_ok(offset: u64, len: usize, size: u64) -> Result<u64, ()> {
    if !offset.is_multiple_of(512) || len == 0 || !len.is_multiple_of(512) {
        return Err(());
    }
    offset
        .checked_add(len as u64)
        .filter(|&end| end <= size)
        .ok_or(())
}

impl fat::BlockDevice for MemImage {
    fn size_bytes(&self) -> u64 {
        self.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        sector_range_ok(offset, buf.len(), self.len()).map_err(|_| fat::Error::OutOfRange)?;
        let data = self.0.borrow();
        buf.copy_from_slice(&data[offset as usize..offset as usize + buf.len()]);
        Ok(())
    }

    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), fat::Error> {
        sector_range_ok(offset, buf.len(), self.len()).map_err(|_| fat::Error::OutOfRange)?;
        let mut data = self.0.borrow_mut();
        data[offset as usize..offset as usize + buf.len()].copy_from_slice(buf);
        Ok(())
    }
}

impl gptwire::Device for MemImage {
    fn size_bytes(&self) -> u64 {
        self.len()
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), gptwire::Error> {
        sector_range_ok(offset, buf.len(), self.len()).map_err(|_| gptwire::Error::OutOfRange)?;
        let data = self.0.borrow();
        buf.copy_from_slice(&data[offset as usize..offset as usize + buf.len()]);
        Ok(())
    }
    // `write_at` keeps the trait's default ReadOnly refusal: the host
    // verifier only ever reads `target.img`.
}

/// One partition (a byte window) of a [`MemImage`], as a read-only
/// `fat::BlockDevice` — the host verifier's p2 mount.
struct PartSlice<'a>(
    &'a MemImage,
    /* first byte */ u64,
    /* bytes */ u64,
);

impl fat::BlockDevice for PartSlice<'_> {
    fn size_bytes(&self) -> u64 {
        self.2
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.2, offset, buf.len())?;
        let abs = self.1.checked_add(offset).ok_or(fat::Error::OutOfRange)?;
        self.0.read_at(abs, buf)
    }
}

/// G6 host-side proof of the **pushed pack** (docs/git-ssh-deps.md §A.4
/// row G6). The in-container mock captured the bytes the guest actually
/// uploaded (`push-capture.bin`); this function:
///
/// 1. frames the captured HTTP request (`POST /git-receive-pack`,
///    `Content-Length` exact) and parses the v0 command section with
///    `git-pktline` — one `<old> <new> refs/heads/main\0report-status`
///    command (the advertised placeholder as `old`, checked), a flush,
///    then the pack;
/// 2. decodes the pack with `git-pack` (independent of the encoder: the
///    trailer SHA-1 and every object id are re-derived) and requires it
///    to hold **exactly** the local commit's reachable graph — commit,
///    trees, blobs — with the commit's `parent` equal to `.git/shallow`'s
///    fetched head, cross-checked against the `.git` the guest wrote on
///    the source volume (read here through the host `fat` crate);
/// 3. hands the same bytes to **real host git**: `git index-pack
///    --strict`, `cat-file -t/-p` on the pushed commit and `ls-tree -r`
///    (whose line count must equal the pack's blob count). That is the
///    independent implementation check the G4 agent used with `git fsck`
///    — a `fsck` here would report the fetched head as a missing parent,
///    which is exactly what a push omits (the server has it).
fn verify_pushed_pack(root: &Path, disk: &Path) -> bool {
    fn fail(msg: impl std::fmt::Display) -> bool {
        eprintln!("smoke-install: push verify failed: {msg}");
        false
    }

    let capture_path = root.join("target/iso-root/push-capture.bin");
    let capture = match std::fs::read(&capture_path) {
        Ok(bytes) => bytes,
        Err(e) => return fail(format_args!("cannot read {}: {e}", capture_path.display())),
    };
    let Some(sep) = capture.windows(4).position(|w| w == b"\r\n\r\n") else {
        return fail("the captured upload has no HTTP head terminator");
    };
    let head = &capture[..sep];
    let body = &capture[sep + 4..];
    if !head.starts_with(b"POST /git-receive-pack HTTP/1.1") {
        return fail("the captured request is not POST /git-receive-pack");
    }
    match header_content_length(head) {
        Some(len) if len == body.len() => {}
        Some(len) => {
            return fail(format_args!(
                "Content-Length {len} but {} body byte(s) were captured",
                body.len()
            ));
        }
        None => return fail("the captured request has no Content-Length"),
    }

    // --- command section (pkt-lines) --------------------------------
    let mut pos = 0usize;
    let command = match git_pktline::decode(body.get(pos..).unwrap_or_default()) {
        git_pktline::Step::Done {
            consumed,
            pkt: git_pktline::Pkt::Data(line),
        } => {
            pos += consumed;
            line
        }
        other => return fail(format_args!("command pkt-line not found: {other:?}")),
    };
    match git_pktline::decode(body.get(pos..).unwrap_or_default()) {
        git_pktline::Step::Done {
            consumed,
            pkt: git_pktline::Pkt::Flush,
        } => pos += consumed,
        other => {
            return fail(format_args!(
                "command section does not end in a flush: {other:?}"
            ));
        }
    }
    let Some(sp1) = command.iter().position(|&b| b == b' ') else {
        return fail("command line has no first separator");
    };
    let Some(old_hex) = command.get(..sp1) else {
        return fail("command line object id truncated");
    };
    let Some(rest) = command.get(sp1 + 1..) else {
        return fail("command line object id truncated");
    };
    let Some(sp2) = rest.iter().position(|&b| b == b' ') else {
        return fail("command line has no second separator");
    };
    let Some(new_hex) = rest.get(..sp2) else {
        return fail("command line new id truncated");
    };
    let Some(tail) = rest.get(sp2 + 1..) else {
        return fail("command line ref truncated");
    };
    let Some(nul) = tail.iter().position(|&b| b == 0) else {
        return fail("command line has no capability NUL");
    };
    let (Some(name), Some(caps)) = (tail.get(..nul), tail.get(nul + 1..)) else {
        return fail("command line ref/caps truncated");
    };
    if old_hex != PUSH_OLD_OID.as_bytes() {
        return fail("command `old` is not the advertised placeholder");
    }
    if name != b"refs/heads/main" {
        return fail("command does not push refs/heads/main");
    }
    if caps.strip_suffix(b"\n").unwrap_or(caps) != b"report-status" {
        return fail("command does not ask for report-status");
    }
    let new_oid = match git_store::parse_oid(new_hex) {
        Ok(oid) => oid,
        Err(_) => return fail("command `new` is not a 40-hex object id"),
    };

    // --- the pack ---------------------------------------------------
    let pack = body.get(pos..).unwrap_or_default();
    if !pack.starts_with(git_pack::PACK_MAGIC.as_slice()) {
        return fail("the body after the flush is not a packfile");
    }
    let (objects, index) = match git_pack::decode_with_index(pack) {
        Ok(decoded) => decoded,
        Err(e) => return fail(format_args!("git-pack refused the pushed pack: {e:?}")),
    };
    if objects.len() != index.len() {
        return fail("the pack index does not cover every object");
    }
    let mut by_oid: std::collections::BTreeMap<[u8; 20], &git_pack::Object> =
        std::collections::BTreeMap::new();
    for object in &objects {
        if by_oid.insert(object.oid(), object).is_some() {
            return fail("the pushed pack holds a duplicate object id");
        }
    }

    // --- the store the guest wrote, read independently --------------
    let image = match std::fs::read(disk) {
        Ok(bytes) => MemImage::from_vec(bytes),
        Err(e) => return fail(format_args!("cannot read {}: {e}", disk.display())),
    };
    let fs = match fat::Fat16::mount(&image) {
        Ok(fs) => fs,
        Err(e) => return fail(format_args!("source volume does not mount: {e:?}")),
    };
    let mut buf = vec![0u8; 64 * 1024];
    let n = match fs.read_file("/.git/refs/heads/main", &mut buf) {
        Ok(n) => n,
        Err(e) => return fail(format_args!("/.git/refs/heads/main: {e:?}")),
    };
    let ref_oid = match git_store::parse_ref(&buf[..n]) {
        Ok(oid) => oid,
        Err(_) => return fail("/.git/refs/heads/main is not a 40-hex ref"),
    };
    if ref_oid != new_oid {
        return fail(format_args!(
            "command `new` {} is not the local ref {}",
            hex40(&new_oid),
            hex40(&ref_oid)
        ));
    }
    let n = match fs.read_file("/.git/shallow", &mut buf) {
        Ok(n) => n,
        Err(e) => return fail(format_args!("/.git/shallow: {e:?}")),
    };
    let base_oid = match git_store::parse_ref(&buf[..n]) {
        Ok(oid) => oid,
        Err(_) => return fail("/.git/shallow is not a 40-hex ref"),
    };
    // The advertised head itself, as the guest stored it (a zlib loose
    // object). It is *not* in the pack — a push omits what the server
    // already has — but seeding it lets real `git index-pack --strict`
    // run its connectivity check against server-like state instead of
    // failing on exactly that correct omission.
    let mut loose_path = Vec::from(&b"/.git/"[..]);
    loose_path.extend_from_slice(&git_store::loose_path(&base_oid));
    let loose_path = match std::str::from_utf8(&loose_path) {
        Ok(path) => path.to_string(),
        Err(_) => return fail("loose object path is not ASCII"),
    };
    let n = match fs.read_file(&loose_path, &mut buf) {
        Ok(n) => n,
        Err(e) => return fail(format_args!("{loose_path}: {e:?}")),
    };
    let base_object = buf[..n].to_vec();

    // --- exact reachable set ---------------------------------------
    let Some(commit) = by_oid.get(&new_oid) else {
        return fail("the pushed pack does not contain the local commit");
    };
    if commit.kind != git_pack::Kind::Commit {
        return fail("the local ref object is not a commit");
    }
    if !commit_parent_is(&commit.data, &base_oid) {
        return fail("the pushed commit's parent is not the shallow boundary");
    }
    let root_tree = match git_pack::parse_commit_tree(&commit.data) {
        Ok(tree) => tree,
        Err(e) => return fail(format_args!("pushed commit refused: {e:?}")),
    };
    let mut reachable: std::collections::BTreeMap<[u8; 20], git_pack::Kind> =
        std::collections::BTreeMap::new();
    reachable.insert(new_oid, git_pack::Kind::Commit);
    reachable.insert(root_tree, git_pack::Kind::Tree);
    let mut pending = vec![root_tree];
    let mut trees = 0usize;
    // Paths, not unique blobs: `git ls-tree -r` lists one line per tree
    // entry, and the same blob may appear at two paths.
    let mut paths = 0usize;
    while let Some(tree_oid) = pending.pop() {
        let Some(tree) = by_oid.get(&tree_oid) else {
            return fail(format_args!(
                "tree {} is missing from the pack",
                hex40(&tree_oid)
            ));
        };
        if tree.kind != git_pack::Kind::Tree {
            return fail(format_args!("{} is not a tree", hex40(&tree_oid)));
        }
        trees += 1;
        let mut offset = 0usize;
        while offset < tree.data.len() {
            let (entry, consumed) = match git_pack::parse_tree_entry(&tree.data[offset..]) {
                Ok(parsed) => parsed,
                Err(e) => return fail(format_args!("pushed tree refused: {e:?}")),
            };
            offset = match offset.checked_add(consumed) {
                Some(next) => next,
                None => return fail("tree entry offset overflow"),
            };
            match entry.mode {
                git_pack::EntryMode::Tree => {
                    if let std::collections::btree_map::Entry::Vacant(slot) =
                        reachable.entry(entry.oid)
                    {
                        slot.insert(git_pack::Kind::Tree);
                        pending.push(entry.oid);
                    }
                }
                git_pack::EntryMode::Blob
                | git_pack::EntryMode::Executable
                | git_pack::EntryMode::Symlink => {
                    reachable.entry(entry.oid).or_insert(git_pack::Kind::Blob);
                    paths += 1;
                }
                // The store skips gitlinks (their commit is not in a
                // shallow fetch); one appearing in the pushed pack is a
                // graph this proof cannot vouch for.
                git_pack::EntryMode::Gitlink => {
                    return fail("the pushed tree names a gitlink");
                }
            }
        }
    }
    if reachable.len() != objects.len() {
        return fail(format_args!(
            "pack holds {} object(s) but only {} are reachable from the pushed commit",
            objects.len(),
            reachable.len()
        ));
    }
    for (oid, kind) in &reachable {
        match by_oid.get(oid) {
            Some(object) if object.kind == *kind => {}
            Some(_) => return fail("a reachable object has the wrong type in the pack"),
            None => return fail("a reachable object is missing from the pack"),
        }
    }
    let blobs = reachable
        .values()
        .filter(|kind| **kind == git_pack::Kind::Blob)
        .count();
    println!(
        "smoke-install: push pack ok — {} object(s) reachable from {}, \
         pack {} B (1 commit, {} tree(s), {} blob(s) at {} path(s), parent {} = .git/shallow)",
        objects.len(),
        hex40(&new_oid),
        pack.len(),
        trees,
        blobs,
        paths,
        hex40(&base_oid),
    );

    // --- independent implementation: real host git ------------------
    let commit_hex = hex40(&new_oid);
    let tree_hex = hex40(&root_tree);
    let base_hex = hex40(&base_oid);
    if !host_git_accepts_pack(
        root,
        pack,
        &commit_hex,
        &tree_hex,
        paths,
        &base_oid,
        &base_object,
    ) {
        return false;
    }
    println!(
        "smoke-install: host git accepted the pushed pack (index-pack --strict with the \
         advertised head {base_hex} seeded as the shallow boundary, cat-file commit \
         {commit_hex}, ls-tree -r {tree_hex} = {paths} path(s))"
    );
    true
}

/// Lowercase hex of an object id (host-side reporting).
fn hex40(oid: &[u8; 20]) -> String {
    String::from_utf8_lossy(&git_store::hex_oid(oid)).into_owned()
}

/// True when a commit object's second line is exactly `parent <oid>`
/// (git's commit format: `tree`, then zero or more `parent` lines).
fn commit_parent_is(data: &[u8], parent: &[u8; 20]) -> bool {
    let mut lines = data.split(|&b| b == b'\n');
    let _tree = lines.next();
    let Some(line) = lines.next() else {
        return false;
    };
    let Some(hex) = line.strip_prefix(b"parent ") else {
        return false;
    };
    match git_store::parse_oid(hex) {
        Ok(oid) => oid == *parent,
        Err(_) => false,
    }
}

/// Hand the pushed pack to **real host `git`** in a throwaway bare repo:
/// `index-pack --strict` (pack checksum, object hashes, link and
/// connectivity checks), `cat-file -t/-p` on the pushed commit (type +
/// tree line) and `ls-tree -r` (whose line count must equal the pack's
/// path count).
///
/// The pack's parent commit is deliberately absent — it is the server's
/// own head, which a push never resends. To let `--strict`'s
/// connectivity check pass **for the right reason**, the advertised head
/// (`base`, read from the guest's own `.git/objects` as its zlib bytes)
/// is seeded as a loose object and named in `$GIT_DIR/shallow`: exactly
/// the state a real server is in (it has the old head, and this clone is
/// shallow there), so the check proves the pushed pack completes that
/// graph rather than merely decoding.
fn host_git_accepts_pack(
    root: &Path,
    pack: &[u8],
    commit_hex: &str,
    tree_hex: &str,
    paths: usize,
    base: &[u8; 20],
    base_object: &[u8],
) -> bool {
    fn fail(msg: impl std::fmt::Display) -> bool {
        eprintln!("smoke-install: host git check failed: {msg}");
        false
    }
    let dir = root.join("target/push-check");
    let _ = std::fs::remove_dir_all(&dir);
    let run = |args: &[&str]| -> Result<std::process::Output, std::io::Error> {
        Command::new("git")
            .arg("--git-dir")
            .arg(&dir)
            .args(args)
            .output()
    };
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return fail(format_args!("cannot create {}: {e}", dir.display()));
    }
    match Command::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&dir)
        .output()
    {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return fail(format_args!(
                "git init failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return fail(format_args!("cannot run git: {e}")),
    }
    let pack_dir = dir.join("objects/pack");
    if let Err(e) = std::fs::create_dir_all(&pack_dir) {
        return fail(format_args!("cannot create {}: {e}", pack_dir.display()));
    }
    // Seed the server's advertised head + the shallow boundary (see the
    // function docs). The bytes are the guest's own zlib loose object,
    // copied verbatim — git's loose-object layout.
    let base_hex = hex40(base);
    let Some((prefix, suffix)) = base_hex.split_at_checked(2) else {
        return fail("object id is too short");
    };
    let loose_dir = dir.join("objects").join(prefix);
    if let Err(e) = std::fs::create_dir_all(&loose_dir) {
        return fail(format_args!("cannot create {}: {e}", loose_dir.display()));
    }
    if let Err(e) = std::fs::write(loose_dir.join(suffix), base_object) {
        return fail(format_args!("cannot seed the advertised head: {e}"));
    }
    if let Err(e) = std::fs::write(dir.join("shallow"), format!("{base_hex}\n")) {
        return fail(format_args!("cannot write the shallow boundary: {e}"));
    }
    let pack_path = pack_dir.join("pack-reemplazo.pack");
    if let Err(e) = std::fs::write(&pack_path, pack) {
        return fail(format_args!("cannot write the pack: {e}"));
    }
    let pack_arg = pack_path.display().to_string();
    match run(&["index-pack", "--strict", &pack_arg]) {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            return fail(format_args!(
                "git index-pack --strict refused the pack: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return fail(format_args!("cannot run git index-pack: {e}")),
    }
    match run(&["cat-file", "-t", commit_hex]) {
        Ok(out) if out.status.success() && out.stdout.trim_ascii() == b"commit" => {}
        Ok(out) => {
            return fail(format_args!(
                "git cat-file -t {commit_hex} did not answer `commit` ({} {})",
                String::from_utf8_lossy(&out.stdout).trim(),
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return fail(format_args!("cannot run git cat-file: {e}")),
    }
    match run(&["cat-file", "-p", commit_hex]) {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            if !text.lines().any(|line| line == format!("tree {tree_hex}")) {
                return fail("git cat-file -p does not name the pushed tree");
            }
        }
        Ok(out) => {
            return fail(format_args!(
                "git cat-file -p failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return fail(format_args!("cannot run git cat-file: {e}")),
    }
    match run(&["ls-tree", "-r", commit_hex]) {
        Ok(out) if out.status.success() => {
            let lines = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|line| !line.trim().is_empty())
                .count();
            if lines != paths {
                return fail(format_args!(
                    "git ls-tree -r lists {lines} path(s), the pack's trees hold {paths}"
                ));
            }
        }
        Ok(out) => {
            return fail(format_args!(
                "git ls-tree -r failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Err(e) => return fail(format_args!("cannot run git ls-tree: {e}")),
    }
    let _ = std::fs::remove_dir_all(&dir);
    true
}

/// Host-side verification of `target.img` after the VM passed —
/// docs/installer.md §7.3's "assert after QEMU exits". Parses the
/// GPT with `gptwire` (independent of the kernel process that wrote
/// it — a different process, and the kernel's own write already had
/// to survive `gptwire::read` *inside the guest* first), checks the
/// p1/p2 layout the installer promised, mounts p2 through `fat` and
/// requires both payload files byte-exact. Returns `false` (with a
/// reason) on any mismatch.
fn verify_installed_image(path: &Path) -> bool {
    fn fail(msg: impl core::fmt::Display) -> bool {
        eprintln!("smoke-install: host verify failed: {msg}");
        false
    }

    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => return fail(format_args!("cannot read {}: {e}", path.display())),
    };
    let img = MemImage::from_vec(data);
    let gpt = match gptwire::read(&img) {
        Ok(g) => g,
        Err(e) => return fail(format_args!("target GPT: {e:?}")),
    };
    let Some((_, last_usable)) = gptwire::usable_range(img.len()) else {
        return fail("target too small for the fixed GPT layout");
    };
    let partitions = gpt.partitions();
    if partitions.len() != 2 {
        return fail(format_args!(
            "expected 2 partitions, found {}",
            partitions.len()
        ));
    }
    let p1 = partitions
        .iter()
        .find(|p| p.type_guid == gptwire::TYPE_BIOS_GRUB);
    let p2 = partitions
        .iter()
        .find(|p| p.type_guid == gptwire::TYPE_BASIC_DATA);
    let (Some(p1), Some(p2)) = (p1, p2) else {
        return fail("bios_grub / basic-data partition missing");
    };
    if (p1.first_lba, p1.last_lba) != (P1_FIRST_LBA, P1_LAST_LBA) {
        return fail(format_args!("p1 is {}..{}", p1.first_lba, p1.last_lba));
    }
    if p2.first_lba != P2_FIRST_LBA || p2.last_lba != last_usable {
        return fail(format_args!("p2 is {}..{}", p2.first_lba, p2.last_lba));
    }

    // Mount p2 and require the network installer's final state
    // byte-exact: the payload README, and the installed kernel
    // against the **built kernel binary** on this host — ground truth
    // a corrupted download the guest could not detect still fails.
    let part = PartSlice(
        &img,
        p2.first_lba * 512,
        (p2.last_lba - p2.first_lba + 1) * 512,
    );
    let fs = match fat::Fat16::mount(&part) {
        Ok(fs) => fs,
        Err(e) => return fail(format_args!("p2 does not mount as FAT16: {e:?}")),
    };
    {
        let mut buf = [0u8; 64];
        let n = match fs.read_file("/README.TXT", &mut buf) {
            Ok(n) => n,
            Err(e) => return fail(format_args!("/README.TXT: {e:?}")),
        };
        if n != README_CONTENT.len() || buf[..n] != *README_CONTENT {
            return fail(format_args!(
                "/README.TXT read back {n} bytes, expected exactly {}",
                README_CONTENT.len()
            ));
        }
    }
    let built = match std::fs::read(repo_root().join("target/x86_64-unknown-none/release/kernel")) {
        Ok(bytes) => bytes,
        Err(e) => return fail(format_args!("cannot read the built kernel: {e}")),
    };
    let mut buf = vec![0u8; built.len()];
    let n = match fs.read_file("/KERNEL.ELF", &mut buf) {
        Ok(n) => n,
        Err(e) => return fail(format_args!("/KERNEL.ELF: {e:?}")),
    };
    if n != built.len() || buf[..n] != built[..] {
        return fail(format_args!(
            "/KERNEL.ELF read back {n} bytes, expected the built kernel's {}",
            built.len()
        ));
    }
    // I1b: the disk is *bootable*, not merely populated — LBA0 must be
    // the patched GRUB boot.img and p1 must hold core.img (compared
    // against the ISO-build artifact byte-for-byte, with the same block
    // list the kernel computes; see `verify_grub_image`).
    if let Err(e) = verify_grub_image(&img, p1.first_lba) {
        return fail(e);
    }
    println!(
        "smoke-install: host verify ok — GPT + FAT16 p2 + installed kernel byte-exact ({} B) \
         + GRUB boot.img/core.img on LBA0/p1",
        built.len()
    );
    true
}

/// Host-side proof of I1b's **bootability bytes** (docs/installer.md
/// §8.6): rebuild what the kernel's `install_grub` must have written
/// from the ISO-build artifacts (`target/iso-root/boot/grubpayload.bin`
/// = `boot.img ‖ core.img`, produced by `grub-mkimage` in the tools
/// image) and compare it with the image on disk:
///
/// - LBA0: the artifact's `boot.img` with the BPB + NT-magic/partition
///   area preserved from the image itself, `kernel_sector` =
///   p1's first LBA (unaligned u64 LE at 0x5c), `boot_drive = 0xFF`,
///   and the hard-disk drive-check workaround (`0x66..0x68` = `nop;
///   nop`) — `grub-setup`'s exact patch set; the protective MBR's
///   `0xEE` record and `55 AA` must survive.
/// - p1: `core.img` padded to whole sectors with the block list at
///   488..512 patched (`term`, `start = p1_first + 1`, `len =
///   sectors - 1`, `segment = 0x820`) — the contiguous-embedding block
///   list `grub-setup` emits for a `bios_grub` partition.
fn verify_grub_image(img: &MemImage, p1_first: u64) -> Result<(), String> {
    const BOOT_BYTES: usize = 512;
    const CORE_CAP: usize = 1 << 20;
    let path = repo_root().join("target/iso-root/boot/grubpayload.bin");
    let artifact =
        std::fs::read(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    if artifact.len() < 2 * BOOT_BYTES || artifact.len() > BOOT_BYTES + CORE_CAP {
        return Err(format!(
            "grubpayload.bin is {} B, outside the 1 KiB..=1 MiB+512 B contract",
            artifact.len()
        ));
    }
    let (boot_art, core_art) = artifact.split_at(BOOT_BYTES);
    let core_sectors = core_art.len().div_ceil(BOOT_BYTES);
    let rest = core_sectors
        .checked_sub(1)
        .and_then(|n| u16::try_from(n).ok())
        .ok_or("core.img block-list length does not fit u16")?;

    // --- LBA0: patched boot.img, partition table preserved ---
    let mbr = img.range(0, BOOT_BYTES).ok_or("LBA0 out of range")?;
    let mut expected = boot_art.to_vec();
    expected[0x03..0x5a].copy_from_slice(&mbr[0x03..0x5a]);
    expected[0x1b8..0x1fe].copy_from_slice(&mbr[0x1b8..0x1fe]);
    expected[0x5c..0x64].copy_from_slice(&p1_first.to_le_bytes());
    expected[0x64] = 0xFF;
    expected[0x66] = 0x90;
    expected[0x67] = 0x90;
    if mbr != expected {
        return Err("LBA0 is not the patched GRUB boot.img".into());
    }
    if mbr[0x1be + 4] != 0xEE || mbr[510..512] != [0x55, 0xAA] {
        return Err("protective MBR damaged by the GRUB install".into());
    }

    // --- p1: patched core.img, whole sectors ---
    let mut core = core_art.to_vec();
    core.resize(core_sectors * BOOT_BYTES, 0);
    core[488..500].fill(0); // block-list terminator
    core[500..508].copy_from_slice(&(p1_first + 1).to_le_bytes());
    core[508..510].copy_from_slice(&rest.to_le_bytes());
    core[510..512].copy_from_slice(&0x0820u16.to_le_bytes());
    let on_disk = img
        .range(p1_first * BOOT_BYTES as u64, core.len())
        .ok_or("p1 (bios_grub) is outside the image")?;
    if on_disk != core {
        return Err("p1 does not hold the patched GRUB core.img".into());
    }
    Ok(())
}

/// Boot the ISO headless (optionally with `disks` attached as IDE
/// drives, in order: first = master, second = slave) and require
/// `markers` in order, draining serial output for diagnosis. Shared by
/// `smoke` (no disks) and `smoke_install` (two); `label` prefixes
/// every message (`smoke| …`, `smoke-install: PASS …`).
///
/// `keyboard`: after the boot phase (all markers but the last), type
/// `echo <last marker>` through QEMU's HMP monitor and require that
/// exact line — the keyboard milestone's end-to-end proof. The
/// keyboard phase has its own [`KEYBOARD_PHASE_TIMEOUT`] budget.
fn boot_assert(
    root: &Path,
    label: &str,
    markers: &[&str],
    timeout: Duration,
    disks: &[&Path],
    ahci_disks: &[&Path],
    keyboard: bool,
) -> bool {
    let iso_path = root.join("target/iso-root/os.iso");
    let Some(invocation) = qemu_invocation(
        root,
        &iso_path,
        &vm_container(root, label),
        disks,
        ahci_disks,
    ) else {
        return false;
    };
    drive_vm(root, label, markers, timeout, keyboard, invocation)
}

/// I1b **disk-boot phase**: boot the installed `disk` alone (no ISO) and
/// require the installed kernel's markers in order. Same serial drain
/// and failure dump as [`boot_assert`]; no keyboard phase (the disk
/// boot proves the boot chain, not the input path — `smoke` owns that).
fn boot_assert_disk(
    root: &Path,
    label: &str,
    markers: &[&str],
    timeout: Duration,
    disk: &Path,
) -> bool {
    let iso_dir = match root.join("target/iso-root").canonicalize() {
        Ok(dir) => dir,
        Err(e) => {
            eprintln!("xtask: cannot resolve target/iso-root: {e}");
            return false;
        }
    };
    let Some(invocation) = qemu_invocation_disk(root, &iso_dir, &vm_container(root, label), disk)
    else {
        return false;
    };
    drive_vm(root, label, markers, timeout, false, invocation)
}

/// Spawn `invocation`, drain its serial output, and require `markers` in
/// order (plus the optional keyboard phase). The body shared by the ISO
/// and disk-boot asserts.
fn drive_vm(
    root: &Path,
    label: &str,
    markers: &[&str],
    timeout: Duration,
    keyboard: bool,
    (prog, args, container, mut mock): Invocation,
) -> bool {
    if let Some(name) = &container {
        rm_container(name);
    }

    let mut child = match Command::new(&prog)
        .args(&args)
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("xtask: cannot start {prog}: {e}");
            // The host-backend mock was already spawned — kill it on
            // this exit path too (no orphans).
            if let Some(mock) = mock.as_mut() {
                let _ = mock.kill();
                let _ = mock.wait();
            }
            return false;
        }
    };

    // Drain stdout+stderr in threads; serial (stdout) is where the marker lands.
    let (tx, rx) = mpsc::channel::<String>();
    let mut pipes: Vec<Box<dyn std::io::Read + Send>> = Vec::new();
    if let Some(out) = child.stdout.take() {
        pipes.push(Box::new(out));
    }
    if let Some(err) = child.stderr.take() {
        pipes.push(Box::new(err));
    }
    for pipe in pipes {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(pipe).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
    }
    drop(tx); // channels close when both readers hit EOF → recv errs end the loop

    let mut next_marker = 0usize;
    let mut collected: Vec<String> = Vec::new();

    // Phase 1: boot markers (for the keyboard smoke: up to and
    // including the marker before the keyboard one — SHELL_OK).
    let boot_target = if keyboard {
        markers.len() - 1
    } else {
        markers.len()
    };
    let boot_deadline = Instant::now() + timeout;
    let boot_ok = wait_for_markers(
        &rx,
        markers,
        &mut next_marker,
        &mut collected,
        boot_target,
        boot_deadline,
        false,
    );

    // Phase 2 (keyboard smoke only): type the command through QEMU's
    // monitor, then require the exact KEYBOARD_OK line the shell's
    // echo builtin printed (exact match — the keystroke echo alone
    // does not count).
    let phase_deadline = Instant::now() + KEYBOARD_PHASE_TIMEOUT;
    if keyboard && boot_ok && type_echo_command(root, phase_deadline) {
        wait_for_markers(
            &rx,
            markers,
            &mut next_marker,
            &mut collected,
            markers.len(),
            phase_deadline,
            true,
        );
    }

    let passed = next_marker == markers.len();
    stop_vm(&mut child, container.as_deref(), &mut mock);

    if passed {
        println!("{label}: PASS — kernel reached {}", markers.join(" + "));
    } else {
        let missing = markers[next_marker..].join(" + ");
        let budget = if keyboard && next_marker == markers.len() - 1 {
            format!("within {KEYBOARD_PHASE_TIMEOUT:?} of SHELL_OK")
        } else {
            format!("within {timeout:?}")
        };
        eprintln!("{label}: FAIL — missing {missing} {budget}");
        for line in &collected {
            eprintln!("{label}| {line}");
        }
    }
    passed
}

/// Read serial lines until `*next_marker == target` or `deadline`
/// passes; every line is logged and kept for the failure dump.
///
/// `exact` requires the trimmed line to equal the expected marker
/// instead of merely containing it — used for `KEYBOARD_OK`, which must
/// be the shell's `echo` *output*: the typed characters `echo
/// KEYBOARD_OK` also appear in the input echo, and that alone proves
/// only decoding, not builtin execution.
fn wait_for_markers(
    rx: &mpsc::Receiver<String>,
    markers: &[&str],
    next_marker: &mut usize,
    collected: &mut Vec<String>,
    target: usize,
    deadline: Instant,
    exact: bool,
) -> bool {
    while *next_marker < target {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let Ok(line) = rx.recv_timeout(remaining) else {
            break; // VM exited or channel closed before the target
        };
        println!("smoke| {line}");
        let expected = markers[*next_marker];
        let matched = if exact {
            line.trim() == expected
        } else {
            line.contains(expected)
        };
        if matched {
            *next_marker += 1;
        }
        collected.push(line);
    }
    *next_marker == target
}

/// Connect to QEMU's HMP monitor (bounded retry — it may not be
/// listening yet) and type `echo KEYBOARD_OK` key by key with
/// `sendkey`, followed by Enter. Key names are QEMU's `QKeyCode` enum
/// (qapi/ui.json): letters as-is, `spc` space, `ret` Enter,
/// `shift-<key>` presses the chord (uppercase), `_` is `shift-minus`.
/// QEMU's input queue paces press/delay/release at ~10 ms each and
/// preserves order, so the burst needs no host-side sleeps.
fn type_echo_command(root: &Path, deadline: Instant) -> bool {
    let addr = ("127.0.0.1", monitor_port(root));
    let mut stream = loop {
        match TcpStream::connect(addr) {
            Ok(s) => break s,
            Err(e) if Instant::now() < deadline => {
                println!("smoke| monitor {} not ready ({e}); retrying", addr.1);
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                eprintln!(
                    "smoke: cannot reach QEMU monitor at {}:{}: {e}",
                    addr.0, addr.1
                );
                return false;
            }
        }
    };
    const KEYS: [&str; 17] = [
        "e",
        "c",
        "h",
        "o",
        "spc",
        "shift-k",
        "shift-e",
        "shift-y",
        "shift-b",
        "shift-o",
        "shift-a",
        "shift-r",
        "shift-d",
        "shift-minus",
        "shift-o",
        "shift-k",
        "ret",
    ];
    for key in KEYS {
        if let Err(e) = writeln!(stream, "sendkey {key}") {
            eprintln!("smoke: monitor write failed: {e}");
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Host-side proof of the formatter↔reader contract, before any VM
    /// runs: the image `write_disk_image` emits must mount through the
    /// same `fat` crate the kernel uses and yield `/README.TXT`
    /// byte-for-byte, with the probe magic inside the boot-code area
    /// and the FAT signature where `mount` looks for it.
    #[test]
    fn disk_image_is_a_readable_fat16_volume() {
        let path = std::env::temp_dir().join(format!(
            "reemplazo-fs1-{:016x}.img",
            checkout_hash(&repo_root())
        ));
        write_disk_image(&path).expect("disk image written");
        let data = std::fs::read(&path).expect("disk image readable");
        assert_eq!(data.len() as u64, DISK_IMAGE_BYTES);

        struct Slice<'a>(&'a [u8]);
        impl fat::BlockDevice for Slice<'_> {
            fn size_bytes(&self) -> u64 {
                self.0.len() as u64
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
                if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
                    return Err(fat::Error::OutOfRange);
                }
                let end = offset
                    .checked_add(buf.len() as u64)
                    .ok_or(fat::Error::OutOfRange)?;
                if end > self.0.len() as u64 {
                    return Err(fat::Error::OutOfRange);
                }
                let start = offset as usize;
                buf.copy_from_slice(&self.0[start..start + buf.len()]);
                Ok(())
            }
        }

        let dev = Slice(&data);
        let fs = fat::Fat16::mount(&dev).expect("image mounts as FAT16");
        let mut buf = [0u8; 64];
        let n = fs.read_file("/README.TXT", &mut buf).expect("README.TXT");
        assert_eq!(&buf[..n], README_CONTENT);

        // The probe contract: magic + checksum in the bootstrap area,
        // BPB untouched, signature at the end of the sector.
        let end = DISK_MAGIC_OFFSET + DISK_MAGIC.len();
        assert_eq!(&data[DISK_MAGIC_OFFSET..end], DISK_MAGIC);
        assert_eq!(data[end], magic_checksum());
        assert_eq!(&data[0..11], b"\xEB<\x90MSDOS5.0");
        assert_eq!(data[510], 0x55);
        assert_eq!(data[511], 0xAA);
    }

    /// The target image's contract with `kernel/src/ata.rs`
    /// `probe_target` (installer I1): the wipe marker + its checksum
    /// at offset 62, **no** `55 AA` (never bootable), byte-different
    /// from the source magic at the same offset, and blank zeros
    /// everywhere else — a disk that is provably empty until the
    /// installer writes it.
    #[test]
    fn target_image_carries_only_the_wipe_marker() {
        let path = std::env::temp_dir().join(format!(
            "reemplazo-i1-target-{:016x}.img",
            checkout_hash(&repo_root())
        ));
        write_target_image(&path).expect("target image written");
        let data = std::fs::read(&path).expect("target image readable");
        let _ = std::fs::remove_file(&path);
        assert_eq!(data.len() as u64, DISK_IMAGE_BYTES);

        let end = DISK_MAGIC_OFFSET + TARGET_DISK_MAGIC.len();
        assert_eq!(&data[DISK_MAGIC_OFFSET..end], TARGET_DISK_MAGIC);
        assert_eq!(data[end], wrapping_sum(TARGET_DISK_MAGIC));

        // Not the source magic (the kernel must tell them apart).
        assert_ne!(
            &data[DISK_MAGIC_OFFSET..DISK_MAGIC_OFFSET + DISK_MAGIC.len()],
            DISK_MAGIC
        );
        // Not bootable: no FAT signature, no BPB, blank everywhere else.
        assert_eq!(&data[510..512], &[0x00, 0x00]);
        assert!(data[..DISK_MAGIC_OFFSET].iter().all(|&b| b == 0));
        assert!(data[end + 1..].iter().all(|&b| b == 0));
    }
}
