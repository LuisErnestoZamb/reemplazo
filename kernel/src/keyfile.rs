//! Manual SSH-auth key source (S3, docs/git-ssh-deps.md §B.4 row S3):
//! turn the `ssh-auth` shell builtin's single argument into a 32-byte
//! ed25519 **seed**.
//!
//! Fail-soft by design: a typo, a missing disk or a missing file prints
//! one line and returns to the prompt — the shell must survive it. The
//! seed itself is the one thing this module never prints; the only key
//! material that reaches the log is the *public* blob and its SHA-256
//! fingerprint, derived by `ssh::auth_cmd`.
//!
//! Accepted forms:
//!
//! 1. **64 hex digits typed at the prompt** — `ssh-auth <64 hex>`.
//!    The practical path for a one-off verification run. An
//!    unencrypted OpenSSH key's seed can be extracted on the dev
//!    machine with `openssl pkey -in ~/.ssh/id_ed25519 -text -noout`
//!    (the bytes under `priv:`, colons removed). The typed line stays
//!    in the shell's line buffer until the next command overwrites it
//!    (documented limit — a shell without a secure-input mode), so a
//!    disk-backed file is the safer option when one is available.
//! 2. **A file on a mounted FAT16 volume** — `ssh-auth /KEY.BIN`,
//!    holding either the 32 raw seed bytes or 64 hex digits (surrounding
//!    whitespace is fine). This is how a key travels on a test/installer
//!    disk image (`target/iso-root/disk.img`), never through the prompt.
//!
//! OpenSSH **private-key files** (`-----BEGIN OPENSSH PRIVATE KEY-----`,
//! which is what `~/.ssh/id_ed25519` actually is) are **not parsed
//! here**. PEM parsing is the reason `ssh-key` exists as an option at
//! all, and the S3 probe (recorded in docs/git-ssh-deps.md §B.2) found
//! it would either drag a second dalek/sha2 generation into ring 0
//! (`ssh-key 0.6.1`, needing a `force-soft` override to compile for
//! `x86_64-unknown-none` at all) or require a pre-release
//! (`0.7.0-rc.12`) — for zero S3 benefit, since the seed can be fed
//! directly. PEM parsing therefore stays deferred with the heap/PEM
//! milestone; use the extraction command above until then.

use crate::ata;

/// Largest key file read from disk: 32 raw bytes, or 64 hex digits plus
/// whitespace. Anything larger is refused before a cluster chain is
/// walked.
const KEY_FILE_CAP: usize = 256;

/// Resolve the builtin's argument to a seed, or `None` after printing
/// one line explaining why (the caller then just returns).
pub fn seed(arg: &str) -> Option<[u8; 32]> {
    let arg = arg.trim();
    if arg.is_empty() {
        serial_println!("usage: ssh-auth <64-hex-seed> | <path-on-fat>");
        return None;
    }

    // 1. A hex seed typed at the prompt.
    let mut seed = [0u8; 32];
    if ssh_wire::parse_seed_hex(arg.as_bytes(), &mut seed).is_ok() {
        return Some(seed);
    }

    // 2. A path on the FAT volume. Absolute paths only: the shell has
    //    no working directory, so a bare name is a typo, not a file.
    if !arg.starts_with('/') {
        serial_println!("ssh-auth: not a 64-digit hex seed, and not an absolute FAT path");
        return None;
    }

    let mut file = [0u8; KEY_FILE_CAP];
    let n = read_from_fat(arg, &mut file)?;
    let seed = decode_seed(&file[..n]);
    if seed.is_none() {
        // Never echo the contents — that could be the seed.
        serial_println!("ssh-auth: {arg} is {n} bytes, not 32 raw or 64 hex digits");
    }
    seed
}

/// Interpret key-file bytes as a 32-byte ed25519 seed: 32 raw bytes, or
/// 64 hex digits (surrounding ASCII whitespace allowed). The local copy
/// of the raw bytes is scrubbed before returning — best effort, see
/// `ssh::AuthKey`'s note on what that guarantee is worth.
fn decode_seed(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut seed = [0u8; 32];
    let ok = if bytes.len() == 32 {
        seed.copy_from_slice(bytes);
        true
    } else {
        ssh_wire::parse_seed_hex(bytes, &mut seed).is_ok()
    };
    if !ok {
        seed.fill(0);
        return None;
    }
    Some(seed)
}

/// Read `path` (absolute, `/`-rooted) from the FAT16 volume on the
/// primary ATA channel. Fail-soft: every refusal is one printed line.
///
/// The drive probe prints its usual `BLK_OK` line when it finds the
/// installer volume; the smoke harness only asserts markers in order,
/// so a manual run that re-probes cannot disturb a passing chain.
fn read_from_fat(path: &str, out: &mut [u8]) -> Option<usize> {
    let Some(drive) = crate::ata::probe() else {
        serial_println!("ssh-auth: no ATA drive answered (attach the disk image)");
        return None;
    };
    let disk = KeyDisk(&drive);
    let fs = match fat::Fat16::mount(&disk) {
        Ok(fs) => fs,
        Err(e) => {
            serial_println!("ssh-auth: no FAT16 volume on the drive ({e:?})");
            return None;
        }
    };
    match fs.read_file(path, out) {
        Ok(n) => Some(n),
        Err(e) => {
            serial_println!("ssh-auth: cannot read {path} ({e:?})");
            None
        }
    }
}

/// Read-only `fat::BlockDevice` over the ATA drive — the read half of
/// `fs::AtaDisk` (`write_at` keeps the trait's `ReadOnly` default).
///
/// It is duplicated here on purpose: the installer proof's adapter is
/// private to `crate::fs` and carries the FS2 write path, while this
/// path must never write to the user's disk. If a third reader appears,
/// lift one adapter into `ata`.
struct KeyDisk<'a>(&'a ata::Drive);

impl fat::BlockDevice for KeyDisk<'_> {
    fn size_bytes(&self) -> u64 {
        u64::from(self.0.sectors) * 512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), fat::Error> {
        // PIO moves whole sectors only; `fat` always asks for exactly
        // that, so anything else is a bug on our side (refused, never
        // rounded).
        if !offset.is_multiple_of(512) || buf.is_empty() || !buf.len().is_multiple_of(512) {
            return Err(fat::Error::OutOfRange);
        }
        fat::checked_end(self.size_bytes(), offset, buf.len())?;
        let lba = u32::try_from(offset / 512).map_err(|_| fat::Error::OutOfRange)?;
        if self.0.read_sectors(lba, buf) {
            Ok(())
        } else {
            Err(fat::Error::Read)
        }
    }
}

// ---- S5: the sshd's on-disk configuration -------------------------
//
// A disk that carries a **host key seed** and an `authorized_keys`-style
// file turns the kernel into an sshd for one connection (`cargo xtask
// smoke-ssh`); a disk that carries only a client seed makes the boot
// auto-run the two-VM probe client. Everything else — including the
// installer smoke's disk, which has neither — is silent: no listener,
// no probe, no log line (the 29-marker `smoke` and `smoke-install`
// chains stay untouched).
//
// File names are 8.3 (the `fat` crate writes/reads short names only):
// `/HOST.BIN` (server seed), `/AUTH.KEY` (one `ssh-ed25519 …` line),
// `/CLIENT.BIN` (client seed for the probe). Seeds accept the same two
// encodings as `ssh-auth`: 32 raw bytes or 64 hex digits.

/// The sshd host-key seed on the volume.
pub(crate) const SERVER_SEED_PATH: &str = "/HOST.BIN";
/// The `authorized_keys` file on the volume (one ed25519 line).
pub(crate) const AUTHORIZED_KEYS_PATH: &str = "/AUTH.KEY";
/// The probe client's key seed (second VM of `smoke-ssh`).
pub(crate) const CLIENT_SEED_PATH: &str = "/CLIENT.BIN";

/// Largest `authorized_keys` file accepted (a handful of lines; the
/// milestone uses exactly one).
const AUTHORIZED_CAP: usize = 1024;

/// What an sshd needs from its disk. `client_key` is the raw ed25519
/// public key parsed out of the authorized-keys file at boot, so a
/// malformed file means "no listener", never a listener that cannot
/// authorize anyone.
pub(crate) struct ServerConfig {
    pub host_seed: [u8; 32],
    pub client_key: [u8; 32],
}

/// Read the sshd configuration from `dev`, or `None` **silently** when
/// the volume does not carry one. A file that is present but malformed
/// prints one explanatory line and yields `None`: a typo must not look
/// like "not configured", and it must not stop the boot either.
/// Hardware bring-up module layout: exactly this many bytes.
pub(crate) const MODULE_CONFIG_LEN: usize = 64;

/// The `sshd` multiboot2 module (hw bring-up): host seed ‖ the
/// authorized key's raw 32 bytes. No parsing beyond a length check —
/// the operator-side generator (kept out of this repo) writes exactly
/// this layout; a malformed module is refused, never guessed at.
pub(crate) fn module_config(raw: &[u8]) -> Option<ServerConfig> {
    if raw.len() != MODULE_CONFIG_LEN {
        return None;
    }
    let mut host_seed = [0u8; 32];
    host_seed.copy_from_slice(&raw[..32]);
    let mut client_key = [0u8; 32];
    client_key.copy_from_slice(&raw[32..]);
    Some(ServerConfig {
        host_seed,
        client_key,
    })
}

pub(crate) fn server_config(dev: &ata::Drive) -> Option<ServerConfig> {
    let disk = KeyDisk(dev);
    let fs = fat::Fat16::mount(&disk).ok()?; // not FAT16 → not ours
    let mut raw = [0u8; KEY_FILE_CAP];
    let n = match fs.read_file(SERVER_SEED_PATH, &mut raw) {
        Ok(n) => n,
        Err(fat::Error::NotFound) => return None, // no server key → neutral
        Err(e) => {
            serial_println!("sshd: cannot read {SERVER_SEED_PATH} ({e:?})");
            return None;
        }
    };
    let host_seed = decode_seed(&raw[..n]);
    raw.fill(0);
    let Some(host_seed) = host_seed else {
        serial_println!("sshd: {SERVER_SEED_PATH} is {n} bytes, not 32 raw or 64 hex digits");
        return None;
    };

    let mut authorized = [0u8; AUTHORIZED_CAP];
    let m = match fs.read_file(AUTHORIZED_KEYS_PATH, &mut authorized) {
        Ok(m) => m,
        Err(fat::Error::NotFound) => {
            serial_println!("sshd: no {AUTHORIZED_KEYS_PATH} on the volume; not listening");
            return None;
        }
        Err(e) => {
            serial_println!("sshd: cannot read {AUTHORIZED_KEYS_PATH} ({e:?})");
            return None;
        }
    };
    let mut client_key = [0u8; 32];
    if ssh_wire::parse_authorized_key(&authorized[..m], &mut client_key).is_err() {
        serial_println!(
            "sshd: {AUTHORIZED_KEYS_PATH} holds no valid ssh-ed25519 key; not listening"
        );
        return None;
    }
    serial_println!("sshd: server key and authorized key loaded from the volume");
    Some(ServerConfig {
        host_seed,
        client_key,
    })
}

/// Read the probe client's seed from `dev`, or `None` silently. The
/// seed itself never reaches the log.
pub(crate) fn client_seed(dev: &ata::Drive) -> Option<[u8; 32]> {
    let disk = KeyDisk(dev);
    let fs = fat::Fat16::mount(&disk).ok()?;
    let mut raw = [0u8; KEY_FILE_CAP];
    let n = match fs.read_file(CLIENT_SEED_PATH, &mut raw) {
        Ok(n) => n,
        Err(_) => return None, // absent (or unreadable) → no probe
    };
    let seed = decode_seed(&raw[..n]);
    raw.fill(0);
    if seed.is_none() {
        serial_println!("sshd-probe: {CLIENT_SEED_PATH} is {n} bytes, not 32 raw or 64 hex digits");
    }
    seed
}
