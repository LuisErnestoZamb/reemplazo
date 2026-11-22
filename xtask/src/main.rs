//! xtask: build, package, and run the OS.
//!
//! Usage (from repo root): `cargo xtask <command>`
//!   check   fmt --check + clippy + host tests + kernel cross-build
//!   build   cross-compile the kernel (x86_64-unknown-none, release)
//!   iso     package target image as bootable ISO (GRUB i386-pc)
//!   smoke   boot the ISO headless; assert serial markers in order,
//!           then type a command through QEMU's monitor (KEYBOARD_OK)
//!   smoke-install  boot with a blank IDE disk; assert BLK_OK (installer m1)
//!   run     build + iso + boot interactively (serial on stdio; keys
//!           can also be injected via the printed monitor address)
//!
//! Backends: grub-mkrescue always runs in the `reemplazo-tools` container
//! (no native macOS build). QEMU prefers a host `qemu-system-x86_64` and
//! falls back to the same container (Homebrew can't build QEMU on macOS 13).

use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio, exit};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Containerized grub-mkrescue + qemu-system-x86_64 (tools/Dockerfile).
const TOOLS_IMAGE: &str = "reemplazo-tools";
/// Boot-phase budget: every serial marker up to `SHELL_OK` must appear
/// within this. The keyboard phase afterwards has its own deadline
/// ([`KEYBOARD_PHASE_TIMEOUT`]) because it starts only once the shell
/// is up.
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Budget for connecting to QEMU's monitor, typing `echo KEYBOARD_OK`
/// with `sendkey`, and waiting for the shell's output. QEMU paces its
/// input queue at ~10 ms per press/delay/release (≈1 s for the
/// 17-key sequence), so this is generous headroom for a phase that
/// should take about a second.
const KEYBOARD_PHASE_TIMEOUT: Duration = Duration::from_secs(15);

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
    49152 + (checkout_hash(root) % 16384) as u16
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let root = repo_root();
    let ok = match cmd.as_str() {
        "check" => check(&root),
        "build" => build_kernel(&root),
        "iso" => iso(&root),
        "smoke" => smoke(&root),
        "smoke-install" => smoke_install(&root),
        "run" => run(&root),
        _ => {
            eprintln!("usage: cargo xtask <check|build|iso|smoke|smoke-install|run>");
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
                "git-pktline",
                "-p",
                "ssh-wire",
                "-p",
                "sky2-wire",
                "-p",
                "mbi",
                "-p",
                "html",
                "-p",
                "net",
                "-p",
                "pci",
                "-p",
                "rtc",
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
                "test",
                "-p",
                "xtask",
                "-p",
                "git-pktline",
                "-p",
                "ssh-wire",
                "-p",
                "sky2-wire",
                "-p",
                "html",
                "-p",
                "mbi",
                "-p",
                "net",
                "-p",
                "pci",
                "-p",
                "rtc",
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

fn iso(root: &Path) -> bool {
    if !build_kernel(root) {
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
    // Image tag is cheap to rebuild; Docker layer cache makes re-runs fast.
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
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
    vec![
        "-m".into(),
        "256M".into(),
        "-cdrom".into(),
        iso.into(),
        "-serial".into(),
        "stdio".into(),
        "-monitor".into(),
        monitor.into(),
        "-display".into(),
        "none".into(),
        "-no-reboot".into(),
        // User-mode networking (slirp): the e1000 TX/RX test needs a
        // peer that answers ARP (gateway 10.0.2.2). Explicit device
        // (with fixed MAC) instead of relying on QEMU's implicit default.
        "-netdev".into(),
        "user,id=net0".into(),
        "-device".into(),
        "e1000,netdev=net0,mac=52:54:00:12:34:56".into(),
    ]
}

fn host_qemu() -> bool {
    matches!(
        Command::new("qemu-system-x86_64").arg("--version").output(),
        Ok(o) if o.status.success()
    )
}

/// `(program, args, container_name)` to boot `iso_path`; `disk`, when
/// set, is attached as a raw IDE drive (`smoke-install`'s blank image —
/// it lives beside `os.iso`, so the container sees it at `/iso/<name>`).
/// Host QEMU first; otherwise build the toolchain image and run in Docker.
/// `container` is the fixed name used for force-cleanup of stale VMs.
/// Both backends get an HMP monitor on this checkout's [`monitor_port`]:
/// host QEMU binds `127.0.0.1` itself, the container publishes its
/// `0.0.0.0` listener with `-p 127.0.0.1:PORT:PORT`.
fn qemu_invocation(
    root: &Path,
    iso_path: &Path,
    container: &str,
    disk: Option<&Path>,
) -> Option<(String, Vec<String>, Option<String>)> {
    let port = monitor_port(root);
    if host_qemu() {
        let iso = iso_path.display().to_string();
        let monitor = format!("tcp:127.0.0.1:{port},server,nowait");
        let mut args = qemu_std_args(&iso, &monitor);
        if let Some(d) = disk {
            args.push("-drive".into());
            args.push(format!("file={},if=ide,format=raw", d.display()));
        }
        return Some(("qemu-system-x86_64".into(), args, None));
    }
    if !sh(root, "docker", &["build", "-t", TOOLS_IMAGE, "tools"]) {
        return None;
    }
    let iso_dir = iso_path.parent()?.display().to_string();
    let mut args: Vec<String> = vec![
        "run".into(),
        "--rm".into(),
        "-i".into(),
        "--name".into(),
        container.into(),
        "-v".into(),
        format!("{iso_dir}:/iso"),
        // Publish the monitor to the host loopback (see `qemu_std_args`:
        // QEMU binds the container's 0.0.0.0, `-p` forwards to eth0).
        "-p".into(),
        format!("127.0.0.1:{port}:{port}"),
        TOOLS_IMAGE.into(),
        "qemu-system-x86_64".into(),
    ];
    let monitor = format!("tcp:0.0.0.0:{port},server,nowait");
    args.extend(qemu_std_args("/iso/os.iso", &monitor));
    if let Some(d) = disk {
        // The iso dir is bind-mounted at /iso and the image was created
        // inside it (see `smoke_install`), so it's visible at /iso/<name>.
        let name = d.file_name()?.to_str()?;
        args.push("-drive".into());
        args.push(format!("file=/iso/{name},if=ide,format=raw"));
    }
    Some(("docker".into(), args, Some(container.into())))
}

/// Remove a container by name if present (stale VM from a killed session).
fn rm_container(name: &str) {
    let _ = Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

fn stop_vm(child: &mut Child, container: Option<&str>) {
    let _ = child.kill();
    let _ = child.wait();
    if let Some(name) = container {
        rm_container(name);
    }
}

fn run(root: &Path) -> bool {
    if !iso(root) {
        return false;
    }
    let iso_path = root.join("target/iso-root/os.iso");
    let Some((prog, args, container)) =
        qemu_invocation(root, &iso_path, &vm_container(root, "run"), None)
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

/// Machine-checked boot test: boot the ISO headless and require each
/// milestone's serial marker in order — `BOOT_OK` (Multiboot2 parse),
/// `MEM_OK` (frame-allocator selftest), `ALLOC_OK` (kernel heap: `Vec`
/// push/check/drop round-trip), `PCI_OK` (config scan),
/// `E1000_OK` (NIC probe + MMIO + MAC), `NET_OK` (TX/RX rings + ARP
/// roundtrip through slirp), `PING_OK` (IPv4/ICMP echo with validated
/// checksums), `DHCP_OK` (full DISCOVER/OFFER/REQUEST/ACK lease),
/// `DNS_OK` (RFC 1035 A lookup for github.com through the leased
/// server), `TCP_OK` (RFC 9293 connect + HTTP GET + FIN close against
/// github.com:80), `INT_OK` (IDT + PIC remap + PIT ticks + int3
/// resume), `TUI_OK` (A1 screen layer: the demo frame rendered into
/// the VGA text buffer and read back from `0xb8000`) — within
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
/// (carve + global allocator), PCI scan, e1000 driver, network path,
/// DHCP/DNS/TCP clients, TLS and HTTP clients, interrupt path (IDT,
/// stubs, EOI, timer), the A1 screen layer (cell diff flush into the
/// text buffer, ratatui backend, full-screen frame readback), the serial
/// shell coming up, or the keyboard path (i8042 bring-up, scancode
/// decode, input multiplexing) — so it gates every milestone in the
/// chain.
///
/// It runs **without a disk**, so the `ata::probe` that sits between
/// `PCI_OK` and `E1000_OK` stays silent here.
fn smoke(root: &Path) -> bool {
    const MARKERS: [&str; 20] = [
        "BOOT_OK",
        "VGA_OK",
        "MEM_OK",
        "ALLOC_OK",
        "RTC_OK",
        "PCI_OK",
        "E1000_OK",
        "NET_OK",
        "PING_OK",
        "DHCP_OK",
        "DNS_OK",
        "TCP_OK",
        "TLS_OK",
        "HTTP_OK",
        "GIT_LSREMOTE_OK",
        "SSH_KEXINIT_OK",
        "INT_OK",
        "TUI_OK",
        "SHELL_OK",
        "KEYBOARD_OK",
    ];
    if !iso(root) {
        return false;
    }
    boot_assert(root, "smoke", &MARKERS, None, true)
}

/// Installer milestone 1 (`BLK_OK`): build the ISO, create a blank
/// 64 MiB `target/iso-root/disk.img` carrying the magic pattern at
/// LBA0 (see `write_disk_image`), boot with the image attached as an
/// IDE drive, and require the kernel's `BLK_OK` marker — printed only
/// when `ata::probe` IDENTIFYs a drive *and* LBA0 validates.
///
/// Note the image is created **after** `iso()` (which wipes
/// `target/iso-root`) and lives inside it, so the container's `/iso`
/// bind mount exposes it to QEMU at `/iso/disk.img`.
fn smoke_install(root: &Path) -> bool {
    if !iso(root) {
        return false;
    }
    let disk = root.join("target/iso-root/disk.img");
    if let Err(e) = write_disk_image(&disk) {
        eprintln!("xtask: cannot create {}: {e}", disk.display());
        return false;
    }
    boot_assert(root, "smoke-install", &["BLK_OK"], Some(&disk), false)
}

/// Fixed installer-smoke disk size: 64 MiB is plenty for the installer
/// milestones (payload ≈1 MB) and cheap to (re)create every run.
const DISK_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Magic pattern at LBA0 of the installer smoke's disk — byte-identical
/// to `MAGIC` in `kernel/src/ata.rs` (xtask cannot depend on the
/// `no_std` kernel crate, so the bytes are duplicated here).
const DISK_MAGIC: &[u8] = b"reemplazo-disk-v1";

/// Create a zero-filled raw disk image whose LBA0 starts with
/// [`DISK_MAGIC`] followed by its wrapping-sum checksum byte — exactly
/// the pattern `ata::probe` validates. The rest of the image is a
/// sparse hole (reads back as zeros, which is what "blank" means here).
fn write_disk_image(path: &Path) -> std::io::Result<()> {
    let mut f = std::fs::File::create(path)?;
    let mut sector = [0u8; 512];
    sector[..DISK_MAGIC.len()].copy_from_slice(DISK_MAGIC);
    sector[DISK_MAGIC.len()] = DISK_MAGIC.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    f.write_all(&sector)?;
    f.set_len(DISK_IMAGE_BYTES)?;
    f.sync_all()?;
    Ok(())
}

/// Boot the ISO headless (optionally with `disk` attached as an IDE
/// drive) and require `markers` in order, draining serial output for
/// diagnosis. Shared by `smoke` and `smoke_install`; `label` prefixes
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
    disk: Option<&Path>,
    keyboard: bool,
) -> bool {
    let iso_path = root.join("target/iso-root/os.iso");
    let Some((prog, args, container)) =
        qemu_invocation(root, &iso_path, &vm_container(root, label), disk)
    else {
        return false;
    };
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
    let boot_deadline = Instant::now() + SMOKE_TIMEOUT;
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
    stop_vm(&mut child, container.as_deref());

    if passed {
        println!("{label}: PASS — kernel reached {}", markers.join(" + "));
    } else {
        let missing = markers[next_marker..].join(" + ");
        let budget = if keyboard && next_marker == markers.len() - 1 {
            format!("within {KEYBOARD_PHASE_TIMEOUT:?} of SHELL_OK")
        } else {
            format!("within {SMOKE_TIMEOUT:?}")
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
