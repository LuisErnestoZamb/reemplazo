//! git **commit** objects — byte-exact to what `git commit-tree`
//! writes ([gitformat-objects §commit](https://git-scm.com/docs/gitformat-objects#_commit)):
//!
//! ```text
//! tree <40-hex>\n
//! parent <40-hex>\n          (0..n of these; ours: exactly one)
//! author <name> <<email>> <epoch> +0000\n
//! committer <name> <<email>> <epoch> +0000\n
//! \n
//! <message>\n
//! ```
//!
//! Two details that decide the object id:
//!
//! - the timezone is spelled `+0000` (this OS's clock is UTC; the FAT
//!   tree also stores UTC-naive stamps);
//! - the message gets a trailing LF only if it does not already end in
//!   one (`strbuf_complete_line` in `builtin/commit-tree.c`; an empty
//!   message stays empty, so the header/body separator is the last
//!   byte).
//!
//! Identity fields are validated to be printable ASCII without `<`,
//! `>`, NUL or newlines, and the email must contain `@` — that is the
//! subset git itself will round-trip without quoting. Callers own the
//! actual identity: this crate never invents one.

use crate::Error;
use crate::object::{MAX_OBJECT_SIZE, hex_oid};
use alloc::vec::Vec;

/// Most parents a single commit may list here (merge commits of the
/// octopus kind are not a milestone requirement; the cap bounds the
/// encoding).
pub const MAX_PARENTS: usize = 16;

/// An author/committer identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature<'a> {
    /// Display name (e.g. `reemplazo`).
    pub name: &'a [u8],
    /// Mailbox (e.g. `reemplazo@localhost`).
    pub email: &'a [u8],
    /// UTC seconds since the Unix epoch (never negative).
    pub epoch: i64,
}

/// Encode a commit object. `message` is stored verbatim except for the
/// trailing-LF completion described in the module docs.
pub fn encode_commit(
    tree: &[u8; 20],
    parents: &[[u8; 20]],
    author: &Signature<'_>,
    committer: &Signature<'_>,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    if parents.len() > MAX_PARENTS {
        return Err(Error::TooManyParents);
    }
    validate_signature(author)?;
    validate_signature(committer)?;
    if message.len() > MAX_OBJECT_SIZE {
        return Err(Error::ObjectTooLarge);
    }
    if message.contains(&0) {
        return Err(Error::BadMessage);
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"tree ");
    out.extend_from_slice(&hex_oid(tree));
    out.push(b'\n');
    for parent in parents {
        out.extend_from_slice(b"parent ");
        out.extend_from_slice(&hex_oid(parent));
        out.push(b'\n');
    }
    write_ident(&mut out, b"author", author);
    write_ident(&mut out, b"committer", committer);
    out.push(b'\n');
    out.extend_from_slice(message);
    if !message.is_empty() && !message.ends_with(b"\n") {
        out.push(b'\n');
    }
    Ok(out)
}

fn write_ident(out: &mut Vec<u8>, role: &[u8], who: &Signature<'_>) {
    out.extend_from_slice(role);
    out.push(b' ');
    out.extend_from_slice(who.name);
    out.extend_from_slice(b" <");
    out.extend_from_slice(who.email);
    out.extend_from_slice(b"> ");
    push_u64(out, u64::try_from(who.epoch).unwrap_or(0));
    out.extend_from_slice(b" +0000\n");
}

fn validate_signature(who: &Signature<'_>) -> Result<(), Error> {
    if who.name.is_empty() || who.name.len() > 128 {
        return Err(Error::BadIdent);
    }
    if who.email.is_empty() || who.email.len() > 256 || !who.email.contains(&b'@') {
        return Err(Error::BadIdent);
    }
    if who.epoch < 0 {
        return Err(Error::BadIdent);
    }
    for bytes in [who.name, who.email] {
        if !bytes
            .iter()
            .all(|&b| (0x20..=0x7e).contains(&b) && b != b'<' && b != b'>')
        {
            return Err(Error::BadIdent);
        }
    }
    Ok(())
}

fn push_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    loop {
        i -= 1;
        if let Some(slot) = buf.get_mut(i) {
            *slot = b'0' + (n % 10) as u8;
        }
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend(buf.iter().skip(i));
}
