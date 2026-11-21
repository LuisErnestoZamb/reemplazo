//! xtask: build, package, and run the OS.
//!
//! Usage (from repo root): `cargo xtask <command>`
//!   check   fmt --check + clippy + host tests + kernel cross-build
//!   build   cross-compile the kernel (x86_64-unknown-none, release)
//!   iso     package target image as bootable ISO (GRUB i386-pc)
//!   smoke   boot the ISO headless; assert serial prints BOOT_OK (the test)
//!   run     build + iso + boot interactively (serial on stdio)
//!
//! Backends: grub-mkrescue always runs in the `reemplazo-tools` container
//! (no native macOS build). QEMU prefers a host `qemu-system-x86_64` and
//! falls back to the same container (Homebrew can't build QEMU on macOS 13).

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio, exit};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Containerized grub-mkrescue + qemu-system-x86_64 (tools/Dockerfile).
const TOOLS_IMAGE: &str = "reemplazo-tools";
const SMOKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Container name unique to this checkout: `rm_container` works by
/// name, so parallel git worktrees (one per milestone) must not
/// force-remove each other's VMs. `DefaultHasher::new()` uses fixed
/// keys, so the same directory always maps to the same name.
fn vm_container(root: &Path, kind: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    root.hash(&mut hasher);
    format!("reemplazo-{kind}-{:016x}", hasher.finish())
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let root = repo_root();
    let ok = match cmd.as_str() {
        "check" => check(&root),
        "build" => build_kernel(&root),
        "iso" => iso(&root),
        "smoke" => smoke(&root),
        "run" => run(&root),
        _ => {
            eprintln!("usage: cargo xtask <check|build|iso|smoke|run>");
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
    // Host crates (xtask, bootinfo) and kernel are linted separately: the
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
                "bootinfo",
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
                "test", "-p", "xtask", "-p", "bootinfo", "-p", "net", "-p", "pci", "-p", "rtc",
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

/// Standard QEMU arguments for booting `iso` headless with serial on stdio.
fn qemu_std_args(iso: &str) -> Vec<String> {
    vec![
        "-m".into(),
        "256M".into(),
        "-cdrom".into(),
        iso.into(),
        "-serial".into(),
        "stdio".into(),
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

/// `(program, args, container_name)` to boot `iso_path`.
/// Host QEMU first; otherwise build the toolchain image and run in Docker.
/// `container` is the fixed name used for force-cleanup of stale VMs.
fn qemu_invocation(
    root: &Path,
    iso_path: &Path,
    container: &str,
) -> Option<(String, Vec<String>, Option<String>)> {
    if host_qemu() {
        let iso = iso_path.display().to_string();
        return Some(("qemu-system-x86_64".into(), qemu_std_args(&iso), None));
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
        TOOLS_IMAGE.into(),
        "qemu-system-x86_64".into(),
    ];
    args.extend(qemu_std_args("/iso/os.iso"));
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
        qemu_invocation(root, &iso_path, &vm_container(root, "run"))
    else {
        return false;
    };
    if let Some(name) = &container {
        rm_container(name); // stale VM from a previous Ctrl-C
    }
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
/// `MEM_OK` (frame-allocator selftest), `PCI_OK` (config scan),
/// `E1000_OK` (NIC probe + MMIO + MAC), `NET_OK` (TX/RX rings + ARP
/// roundtrip through slirp), `PING_OK` (IPv4/ICMP echo with validated
/// checksums), `DHCP_OK` (full DISCOVER/OFFER/REQUEST/ACK lease),
/// `DNS_OK` (RFC 1035 A lookup for github.com through the leased
/// server), `TCP_OK` (RFC 9293 connect + HTTP GET + FIN close against
/// github.com:80), `INT_OK` (IDT + PIC remap + PIT ticks + int3
/// resume) — within `SMOKE_TIMEOUT`. This is the test that fails on a
/// broken boot path (header, trampoline, GDT, paging, mbi parse),
/// memory path, PCI scan, e1000 driver, network path, DHCP/DNS/TCP
/// clients, TLS and HTTP clients, interrupt path (IDT, stubs, EOI,
/// timer), or the serial shell coming up, so it gates all fourteen
/// milestones.
fn smoke(root: &Path) -> bool {
    const MARKERS: [&str; 14] = [
        "BOOT_OK", "MEM_OK", "RTC_OK", "PCI_OK", "E1000_OK", "NET_OK", "PING_OK", "DHCP_OK",
        "DNS_OK", "TCP_OK", "TLS_OK", "HTTP_OK", "INT_OK", "SHELL_OK",
    ];
    if !iso(root) {
        return false;
    }
    let iso_path = root.join("target/iso-root/os.iso");
    let Some((prog, args, container)) =
        qemu_invocation(root, &iso_path, &vm_container(root, "smoke"))
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

    let deadline = Instant::now() + SMOKE_TIMEOUT;
    let mut next_marker = 0usize;
    let mut collected: Vec<String> = Vec::new();
    while let Ok(line) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        println!("smoke| {line}");
        if line.contains(MARKERS[next_marker]) {
            next_marker += 1;
            if next_marker == MARKERS.len() {
                break;
            }
        }
        collected.push(line);
    }
    let passed = next_marker == MARKERS.len();
    stop_vm(&mut child, container.as_deref());

    if passed {
        println!("smoke: PASS — kernel reached {}", MARKERS.join(" + "));
    } else {
        let missing = MARKERS[next_marker..].join(" + ");
        eprintln!("smoke: FAIL — missing {missing} within {SMOKE_TIMEOUT:?}");
        for line in &collected {
            eprintln!("smoke| {line}");
        }
    }
    passed
}
