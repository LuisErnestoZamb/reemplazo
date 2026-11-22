//! `HEAD` and ref files — the two text files a local store needs.
//!
//! - `.git/HEAD` is a symbolic ref: `ref: refs/heads/<branch>\n`.
//! - `.git/refs/heads/<branch>` is a direct ref: 40 lowercase hex + `\n`.
//!
//! The ref-name grammar is git's `check-ref-format` subset that a
//! branch created by this OS can hit: non-empty, at most 255 bytes, no
//! leading/trailing `/`, no empty components, no component starting
//! with `.` or ending in `.lock`, and none of the ASCII control bytes,
//! space, `~ ^ : ? * [ \`, `..` or `@{`. Non-ASCII (UTF-8) names are
//! allowed, as in git. Anything else is [`Error::BadRef`] — the writer
//! never mangles a name.
//!
//! Parsing is strict: a ref must be exactly 40 lowercase hex characters
//! plus at most one trailing LF (uppercase or a 39-char id is refused —
//! that is a corrupt file, not a ref to interpret), and a symbolic ref
//! must start with `ref: ` and name a valid ref.

use crate::Error;
use crate::object::{hex_oid, parse_oid};
use alloc::vec::Vec;

/// Longest ref name accepted (same bound as a path component budget;
/// git itself has no fixed cap, we need one).
const MAX_REF_LEN: usize = 255;

/// Encode `HEAD` for a short branch name (`main` → `ref: refs/heads/main\n`).
pub fn encode_head(branch: &[u8]) -> Result<Vec<u8>, Error> {
    let mut full = Vec::new();
    full.extend_from_slice(b"refs/heads/");
    full.extend_from_slice(branch);
    if !valid_ref_name(&full) {
        return Err(Error::BadRef);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"ref: ");
    out.extend_from_slice(&full);
    out.push(b'\n');
    Ok(out)
}

/// Parse a symbolic ref file, returning the ref name it points at
/// (`refs/heads/main`) borrowed from `data`. One optional trailing LF
/// is accepted.
pub fn parse_head(data: &[u8]) -> Result<&[u8], Error> {
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    let name = body.strip_prefix(b"ref: ").ok_or(Error::BadRef)?;
    if !valid_ref_name(name) {
        return Err(Error::BadRef);
    }
    Ok(name)
}

/// Encode a direct ref file: 40 lowercase hex + LF.
pub fn encode_ref(oid: &[u8; 20]) -> [u8; 41] {
    let hex = hex_oid(oid);
    let mut out = [0u8; 41];
    out[..40].copy_from_slice(&hex);
    out[40] = b'\n';
    out
}

/// Parse a direct ref file. Exactly one optional trailing LF; anything
/// else is refused.
pub fn parse_ref(data: &[u8]) -> Result<[u8; 20], Error> {
    let body = data.strip_suffix(b"\n").unwrap_or(data);
    parse_oid(body)
}

/// The documented subset of git's `check-ref-format`.
pub fn valid_ref_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > MAX_REF_LEN {
        return false;
    }
    if name == b"@".as_slice() || name.first() == Some(&b'/') || name.last() == Some(&b'/') {
        return false;
    }
    if name.windows(2).any(|w| w == b".." || w == b"@{") {
        return false;
    }
    for &byte in name {
        if byte < 0x20
            || byte == 0x7f
            || matches!(byte, b' ' | b'~' | b'^' | b':' | b'?' | b'*' | b'[' | b'\\')
        {
            return false;
        }
    }
    for component in name.split(|&b| b == b'/') {
        if component.is_empty() || component.first() == Some(&b'.') || component.ends_with(b".lock")
        {
            return false;
        }
    }
    true
}
