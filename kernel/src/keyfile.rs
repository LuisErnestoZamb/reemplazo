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
    if n == 32 {
        // Raw seed bytes.
        seed.copy_from_slice(&file[..32]);
        return Some(seed);
    }
    match ssh_wire::parse_seed_hex(&file[..n], &mut seed) {
        Ok(()) => Some(seed),
        Err(_) => {
            // Never echo the contents — that could be the seed.
            serial_println!("ssh-auth: {arg} is {n} bytes, not 32 raw or 64 hex digits");
            None
        }
    }
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
