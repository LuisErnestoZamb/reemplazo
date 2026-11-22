//! xtask: build, package, and run the OS.
//!
//! Usage (from repo root): `cargo xtask <command>`
//!   check   fmt --check + clippy + host tests + kernel cross-build
//!   build   cross-compile the kernel (x86_64-unknown-none, release)
//!   iso     package target image as bootable ISO (GRUB i386-pc)
//!   smoke   boot the ISO headless; assert serial markers in order,
//!           then type a command through QEMU's monitor (KEYBOARD_OK)
//!   smoke-install  boot with a FAT16 IDE disk; assert BLK_OK + FAT_OK
//!           + FS_WRITE_OK (write + re-mount read-back)
//!   run     build + iso + boot interactively (serial on stdio; keys
//!           can also be injected via the printed monitor address)
//!
//! Backends: grub-mkrescue always runs in the `reemplazo-tools` container
//! (no native macOS build). QEMU prefers a host `qemu-system-x86_64` and
//! falls back to the same container (Homebrew can't build QEMU on macOS 13).

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
                "mbi",
                "-p",
                "html",
                "-p",
                "net",
                "-p",
                "pci",
                "-p",
                "rtc",
                "-p",
                "fat",
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
                "html",
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

/// The in-container mock: a **bounded** loop of `nc` one-shot servers
/// on the container's loopback :8099, backgrounded, then QEMU is
/// `exec`'d — so QEMU becomes the container's main process and, when
/// the container stops (`--rm` / `docker rm -f`), every process in it
/// dies with it: no host-side orphans, which this repo checks with
/// `ps` after every run. `nc` serves the canned response the moment a
/// connection is accepted (HTTP lets the server write first; the
/// guest sends-then-reads), exits per connection when the peer
/// closes, and `|| true` keeps the loop running through a refused
/// bind. stdout/stderr → `/dev/null` so the request bytes the guest
/// sends can never pollute the serial log the markers are read from.
/// Verified end-to-end (`nc -l -s 127.0.0.1 -p 8099` + delayed and
/// sequential clients) in the A3 commit.
const MOCK_LOOP: &str = "for i in 1 2 3 4 5; do \
     nc -l -s 127.0.0.1 -p 8099 < /iso/chat-mock-response.txt > /dev/null 2>&1 || true; \
     done & exec qemu-system-x86_64 \"$@\"";

/// The `xtask chat-mock` subcommand (host-QEMU backend): serve
/// [`chat_mock_response`] on 127.0.0.1:8099 for a bounded number of
/// connections and a bounded lifetime, so a wedged guest can never
/// leave this process running on its own. Spawned as a child by
/// [`qemu_invocation`] and killed in `stop_vm`; also reachable
/// manually for debugging the kernel's `ai` builtin against a host
/// VM.
fn serve_chat_mock(root: &Path) {
    let file = root.join("target/iso-root/chat-mock-response.txt");
    let response = match std::fs::read(&file) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot read {}: {e}", file.display());
            exit(1);
        }
    };
    let listener = match std::net::TcpListener::bind(("127.0.0.1", 8099)) {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("xtask chat-mock: cannot bind 127.0.0.1:8099: {e}");
            exit(1);
        }
    };
    if listener.set_nonblocking(true).is_err() {
        exit(1);
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let mut served = 0usize;
    while served < 5 && Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let _ = stream.set_nonblocking(true); // no client can wedge us
                let _ = stream.write_all(&response);
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
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("xtask chat-mock: accept failed: {e}");
                break;
            }
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
/// `disk`, when set, is attached as a raw IDE drive (`smoke-install`'s
/// blank image — it lives beside `os.iso`, so the container sees it at
/// `/iso/<name>`). Host QEMU first; otherwise build the toolchain image
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
    disk: Option<&Path>,
) -> Option<Invocation> {
    // The A3 mock response must exist before the VM starts: written
    // after `iso()` wiped the dir (the `disk.img` precedent).
    let iso_dir = iso_path.parent()?;
    if let Err(e) = write_chat_mock(iso_dir) {
        eprintln!(
            "xtask: cannot write {}: {e}",
            iso_dir.join("chat-mock-response.txt").display()
        );
        return None;
    }
    let port = monitor_port(root);
    if host_qemu() {
        let iso = iso_path.display().to_string();
        let monitor = format!("tcp:127.0.0.1:{port},server,nowait");
        let mut args = qemu_std_args(&iso, &monitor);
        if let Some(d) = disk {
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
    if let Some(d) = disk {
        // The iso dir is bind-mounted at /iso and the image was created
        // inside it (see `smoke_install`), so it's visible at /iso/<name>.
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
/// pane read back from `0xb8000`) — within
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
/// text buffer, ratatui backend, full-screen frame readback), the A2
/// editor (gap buffer + line index edits with undo/redo, viewport frame
/// readback), the A3 chat client (serde_json request/response over
/// `net::http` POST against the mock + chat-pane readback), the serial
/// shell coming up, or the keyboard path (i8042 bring-up, scancode
/// decode, input multiplexing) — so it gates every milestone in the
/// chain.
///
/// It runs **without a disk**, so the `ata::probe` that sits between
/// `PCI_OK` and `E1000_OK` stays silent here.
fn smoke(root: &Path) -> bool {
    const MARKERS: [&str; 22] = [
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
        "EDITOR_OK",
        "AI_CHAT_OK",
        "SHELL_OK",
        "KEYBOARD_OK",
    ];
    if !iso(root) {
        return false;
    }
    boot_assert(root, "smoke", &MARKERS, None, true)
}

/// Installer milestones 1 + FS1 + FS2 (`BLK_OK`, `FAT_OK`,
/// `FS_WRITE_OK`): build the ISO, write a 64 MiB
/// `target/iso-root/disk.img` that is a **valid FAT16 volume** carrying
/// the `ata` magic in its boot sector's bootstrap area (see
/// [`write_disk_image`]), boot with the image attached as an IDE drive,
/// and require the kernel's `BLK_OK` (the ATA probe accepted LBA0),
/// `FAT_OK` (the kernel mounted that volume and read `/README.TXT`
/// back byte for byte) and `FS_WRITE_OK` (the kernel *wrote*
/// `/RESULT.TXT`, re-mounted from scratch and read it back byte-exact,
/// with `/README.TXT` re-checked for clobbering) in that order.
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
    boot_assert(
        root,
        "smoke-install",
        &["BLK_OK", "FAT_OK", "FS_WRITE_OK"],
        Some(&disk),
        false,
    )
}

/// Fixed installer-smoke disk size: 64 MiB is plenty for the installer
/// milestones (payload ≈1 MB) and cheap to (re)create every run.
const DISK_IMAGE_BYTES: u64 = 64 * 1024 * 1024;

/// Magic pattern at LBA0 of the installer smoke's disk — byte-identical
/// to `MAGIC` in `kernel/src/ata.rs` (xtask cannot depend on the
/// `no_std` kernel crate, so the bytes are duplicated here).
const DISK_MAGIC: &[u8] = b"reemplazo-disk-v1";

/// Byte offset of [`DISK_MAGIC`] inside LBA0 — byte-identical to
/// `MAGIC_OFFSET` in `kernel/src/ata.rs`. LBA0 is a real FAT boot
/// sector (0..3 jump, 3..10 OEM, 11..62 BPB, 510..512 `55 AA`), so the
/// magic lives in the bootstrap area FAT never parses.
const DISK_MAGIC_OFFSET: usize = 62;

/// Wrapping-sum checksum byte that follows [`DISK_MAGIC`] — duplicated
/// from `kernel/src/ata.rs`'s `magic_checksum`.
fn magic_checksum() -> u8 {
    DISK_MAGIC.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
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

/// `/README.TXT`'s content — byte-identical to `README_EXPECTED` in
/// `kernel/src/fs/mod.rs` (host crates cannot depend on the kernel).
const README_CONTENT: &[u8] = b"reemplazo filesystem ok\n";

/// Create a 64 MiB raw disk image that is a valid **FAT16 volume**
/// (superfloppy layout: no partition table, the whole disk is the
/// volume) containing `/README.TXT`, with [`DISK_MAGIC`] + its checksum
/// at [`DISK_MAGIC_OFFSET`] in the boot sector — exactly the two-sided
/// contract `ata::probe` and `kernel/src/fs::prove` validate.
///
/// Formatter choice (FS1): written here in xtask rather than shelling
/// out to `mkfs.fat`, so the image needs no toolchain addition, is
/// byte-reproducible on any host, and is host-verified by the
/// `disk_image_is_a_readable_fat16_volume` test below before any VM
/// runs. Everything not explicitly written stays a sparse zero hole.
fn write_disk_image(path: &Path) -> std::io::Result<()> {
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

    // Two identical FATs: media/end-of-chain bookkeeping plus the one
    // cluster `/README.TXT` occupies, closed with end-of-chain.
    let mut fat = vec![0u8; FAT_SECTORS as usize * SECTOR_SIZE];
    fat[0..2].copy_from_slice(&0xFFF8u16.to_le_bytes()); // cluster 0: media
    fat[2..4].copy_from_slice(&0xFFFFu16.to_le_bytes()); // cluster 1: reserved
    fat[4..6].copy_from_slice(&0xFFFFu16.to_le_bytes()); // cluster 2: EOC
    f.write_all(&fat)?;
    f.write_all(&fat)?;

    // Fixed root directory: `/README.TXT` as a classic 8.3 entry.
    let mut root = vec![0u8; FAT_ROOT_SECTORS as usize * SECTOR_SIZE];
    root[0..8].copy_from_slice(b"README  ");
    root[8..11].copy_from_slice(b"TXT");
    root[11] = 0x20; // archive
    root[26..28].copy_from_slice(&(README_CLUSTER as u16).to_le_bytes());
    root[28..32].copy_from_slice(&(README_CONTENT.len() as u32).to_le_bytes());
    f.write_all(&root)?;

    // Data region: cluster 2 begins here; only the file's bytes are
    // written, the rest of the 4 KiB cluster stays sparse zero.
    f.write_all(README_CONTENT)?;
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
    let Some((prog, args, container, mut mock)) =
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
}
