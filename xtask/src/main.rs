//! xtask: build, package, and run the OS.
//!
//! Usage (from repo root): `cargo xtask <command>`
//!   check   fmt --check + clippy + host tests + kernel cross-build
//!   build   cross-compile the kernel (x86_64-unknown-none, release)
//!   iso     package target image as bootable ISO (GRUB i386-pc)
//!   smoke   boot the ISO headless; assert serial markers in order,
//!           then type a command through QEMU's monitor (KEYBOARD_OK)
//!   smoke-install  boot with a FAT16 source disk + a blank target disk;
//!           assert BLK_OK + FAT_OK + FS_WRITE_OK + FS_TREE_OK + INST_OK
//!           + GIT_CHECKOUT_OK + NETINST_OK, then re-verify target.img
//!           on the host
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
        // Boot the ISO *first*, then the disk (`d` = first CD-ROM,
        // `c` = first hard disk in QEMU's legacy order letters). Since
        // FS1, an attached smoke disk carries a genuine FAT boot sector
        // at LBA0 (0x55 AA + a valid jump), which SeaBIOS is happy to
        // execute — verified in the FS1 milestone: with QEMU's default
        // order the guest hangs in the volume's bootstrap and the ISO
        // never boots. Pinning the ISO first keeps both smokes on GRUB
        // while leaving the disk bootable once a smoke reboots from it
        // without a CD (installer milestone GRUB_OK can pass `order=c`).
        "-boot".into(),
        "order=dc".into(),
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
    ]
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
// process in that container — see [`MOCK_LOOP`]. The host-QEMU
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

/// Write `chat-mock-response.txt` into the ISO dir (bind-mounted at
/// `/iso` in the container, plain file for the host backend). Called
/// from [`qemu_invocation`], i.e. after `iso()` has wiped the dir (the
/// `disk.img` precedent) and before the VM starts — so it is never
/// inside the ISO itself, just beside it.
fn write_chat_mock(iso_dir: &Path) -> std::io::Result<()> {
    std::fs::write(iso_dir.join("chat-mock-response.txt"), chat_mock_response())
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

/// The in-container mock: a **bounded** loop of `nc` one-shot servers
/// on the container's loopback — `:8099` serves the canned chat
/// response, `:8080` serves the canned *payload* response (I2: the
/// guest's `GET /payload.tar` over its own stack) — backgrounded,
/// then QEMU is `exec`'d, so QEMU becomes the container's main
/// process and, when the container stops (`--rm` / `docker rm -f`),
/// every process in it dies with it: no host-side orphans, which this
/// repo checks with `ps` after every run. `nc` serves the canned
/// response the moment a connection is accepted (HTTP lets the server
/// write first; the guest sends-then-reads), exits per connection
/// when the peer closes, and `|| true` keeps the loop running through
/// a refused bind. stdout/stderr → `/dev/null` so the request bytes
/// the guest sends can never pollute the serial log the markers are
/// read from. Verified end-to-end (`nc -l -s 127.0.0.1 -p 8099` +
/// delayed and sequential clients) in the A3 commit; `:8080` is the
/// same shape with `payload-http.txt` (I2).
const MOCK_LOOP: &str = "for i in 1 2 3 4 5; do \
     nc -l -s 127.0.0.1 -p 8099 < /iso/chat-mock-response.txt > /dev/null 2>&1 || true; \
     done & \
     for i in 1 2 3 4 5; do \
     nc -l -s 127.0.0.1 -p 8080 < /iso/payload-http.txt > /dev/null 2>&1 || true; \
     done & exec qemu-system-x86_64 \"$@\"";

/// The `xtask chat-mock` subcommand (host-QEMU backend): serve
/// [`chat_mock_response`] on 127.0.0.1:8099 **and** the I2 payload
/// response on 127.0.0.1:8080 (the container backend's `MOCK_LOOP`
/// does the same two ports with `nc`), for a bounded number of
/// connections and a bounded lifetime, so a wedged guest can never
/// leave this process running on its own. Spawned as a child by
/// [`qemu_invocation`] and killed in `stop_vm`; also reachable
/// manually for debugging the kernel's `ai` builtin against a host
/// VM.
fn serve_chat_mock(root: &Path) {
    let file = root.join("target/iso-root/chat-mock-response.txt");
    let chat = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read {}: {e}", file.display());
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
    let chat_listener = match std::net::TcpListener::bind(("127.0.0.1", 8099)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot bind 127.0.0.1:8099: {e}");
            exit(1);
        }
    };
    let payload_listener = match std::net::TcpListener::bind(("127.0.0.1", 8080)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot bind 127.0.0.1:8080: {e}");
            exit(1);
        }
    };
    if chat_listener.set_nonblocking(true).is_err()
        || payload_listener.set_nonblocking(true).is_err()
    {
        exit(1);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut served = 0usize;
    while served < 10 && Instant::now() < deadline {
        let mut connected = false;
        for (listener, response) in [(&chat_listener, &chat), (&payload_listener, &payload)] {
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
            let _ = stream.write_all(response);
            // Drain the request before closing: closing with
            // unread inbound data sends RST, which can discard the
            // response on the client side. Bounded either way.
            let mut buf = [0u8; 512];
            let drain_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break, // peer finished — clean close
                    Ok(_) => {}
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() >= drain_deadline {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
            served += 1;
        }
        if !connected {
            std::thread::sleep(Duration::from_millis(50));
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
/// host backend only (the container backend runs [`MOCK_LOOP`] inside
/// itself) — every caller must kill it, which `stop_vm` does.
/// Both backends get an HMP monitor on this checkout's [`monitor_port`]:
/// host QEMU binds `127.0.0.1` itself, the container publishes its
/// `0.0.0.0` listener with `-p 127.0.0.1:PORT:PORT`.
fn qemu_invocation(
    root: &Path,
    iso_path: &Path,
    container: &str,
    disks: &[&Path],
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
        MOCK_LOOP.into(),
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
        qemu_invocation(root, &iso_path, &vm_container(root, "run"), &[])
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
/// as a robustness pass) — within
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
/// `0xb8000`), the serial
/// shell coming up, or the keyboard path (i8042 bring-up, scancode
/// decode, input multiplexing) — so it gates every milestone in the
/// chain.
///
/// It runs **without a disk**, so the `ata::probe` that sits between
/// `PCI_OK` and `E1000_OK` stays silent here.
fn smoke(root: &Path) -> bool {
    const MARKERS: [&str; 29] = [
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
        "SHELL_OK",
        "KEYBOARD_OK",
    ];
    if !iso(root) {
        return false;
    }
    boot_assert(root, "smoke", &MARKERS, &[], true)
}

/// Installer milestones 1 + FS1 + FS2 + **I1** + **I2** (`BLK_OK`,
/// `FAT_OK`, `FS_WRITE_OK`, `INST_OK`, `NETINST_OK`): build the ISO, then write **two** 64 MiB
/// images into `target/iso-root` (after `iso()` wiped it): `disk.img`,
/// a valid FAT16 *source* volume ([`write_disk_image`]), and
/// `target.img`, a blank disk carrying only the wipe-marker magic
/// ([`write_target_image`]). Boot with both attached as IDE drives —
/// source first (master, unit 0), target second (slave, unit 1), the
/// order `ata::probe`/`ata::probe_target` enumerate — and require the
/// kernel's `BLK_OK` (ATA probe accepted LBA0), `FAT_OK` (mounted the
/// source volume, `/README.TXT` byte-exact), `FS_WRITE_OK` (wrote
/// `/RESULT.TXT`, re-mounted from scratch, read back with README
/// re-checked) and `INST_OK` (the full install flow on the *target*:
/// GPT written and re-read through `gptwire`, p2 formatted FAT16 with
/// the shared `fat::format_fat16`, payload copied from the source
/// volume, p2 re-mounted and read back byte-exact — see
/// `kernel/src/install.rs`), and `NETINST_OK` (I2: after the boot
/// network chain, the kernel fetches `payload.tar` (the built kernel
/// and README, served by the in-container responder on `10.0.2.2:8080`
/// from `payload-http.txt`, written by [`write_payload_mock`]) over
/// its own stack, walks the ustar headers, reinstalls onto the target
/// and reads every file back byte-exact).
///
/// After the VM passes, [`verify_installed_image`] re-checks
/// `target.img` **on the host** — docs/installer.md §7.3's "assert
/// after QEMU exits": GPT parsed independently of the running kernel,
/// layout checked, and the installed `/KERNEL.ELF` compared
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
    if let Err(e) = write_disk_image(&disk) {
        eprintln!("xtask: cannot create {}: {e}", disk.display());
        return false;
    }
    if let Err(e) = write_target_image(&target) {
        eprintln!("xtask: cannot create {}: {e}", target.display());
        return false;
    }
    let disks: [&Path; 2] = [&disk, &target];
    if !boot_assert(
        root,
        "smoke-install",
        &[
            "BLK_OK",
            "FAT_OK",
            "FS_WRITE_OK",
            "FS_TREE_OK",
            "INST_OK",
            "GIT_CHECKOUT_OK",
            "NETINST_OK",
        ],
        &disks,
        false,
    ) {
        return false;
    }
    verify_installed_image(&target)
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
    println!(
        "smoke-install: host verify ok — GPT + FAT16 p2 + installed kernel byte-exact ({} B)",
        built.len()
    );
    true
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
    disks: &[&Path],
    keyboard: bool,
) -> bool {
    let iso_path = root.join("target/iso-root/os.iso");
    let Some((prog, args, container, mut mock)) =
        qemu_invocation(root, &iso_path, &vm_container(root, label), disks)
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
    stop_vm(&mut child, container.as_deref(), &mut mock);

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
