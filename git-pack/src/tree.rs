//! git **tree** and **commit** object parsing — the object formats a
//! fetch's root commit is walked through (`G3`, docs/git-ssh-deps.md
//! §A.4).
//!
//! Additive companion to the pack decoder: the pack crate already owns
//! every hostile-input parser (see the crate root), and the kernel that
//! *walks* a fetched tree cannot be host-tested (`x86_64-unknown-none`
//! only). Keeping the byte-level tree/commit parsing here gives those
//! formats the same adversarial test treatment as the pack: truncation
//! at every byte boundary, bad modes, missing NUL/separators, short or
//! non-hex ids, slash/`.`/`..` names, non-printable names.
//!
//! Formats (git's [object-format](https://git-scm.com/docs/gitformat-objects)):
//!
//! - tree entry: `<mode-octal> SP <name> NUL <20-byte oid>` repeated;
//!   names are raw bytes, modes are written without leading zeros
//!   (`40000`, `100644`, `100755`, `120000`, `160000`).
//! - commit: starts with `tree <40-hex-oid>\n`.
//!
//! Both parsers are `#![forbid(unsafe_code)]` by the crate root,
//! allocation-free, and fail closed: an unknown mode or a malformed
//! entry is an error, never a skipped byte range.

/// Why a tree entry or commit header was refused. Fail-closed: the
/// caller must discard the object, never continue past the bad bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectError {
    /// The bytes end before a complete `<mode> SP <name> NUL <oid>`.
    Truncated,
    /// The mode is not 1..=6 octal digits or not one of the five git
    /// tree modes.
    BadMode,
    /// The name is empty, `.`/`..`, contains `/`, or has a byte
    /// outside printable ASCII (the project's shared log/path policy).
    BadName,
    /// The commit does not start with `tree <40-hex>\n`.
    BadCommit,
}

/// The five modes a git tree entry can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryMode {
    /// `40000` — a subtree.
    Tree,
    /// `100644` — a regular file.
    Blob,
    /// `100755` — an executable file.
    Executable,
    /// `120000` — a symlink (its blob is the target path).
    Symlink,
    /// `160000` — a gitlink (submodule commit, not an object here).
    Gitlink,
}

impl EntryMode {
    /// Classify a tree-entry mode value (octal, already decoded).
    fn from_value(value: u32) -> Option<EntryMode> {
        match value {
            0o40000 => Some(EntryMode::Tree),
            0o100644 => Some(EntryMode::Blob),
            0o100755 => Some(EntryMode::Executable),
            0o120000 => Some(EntryMode::Symlink),
            0o160000 => Some(EntryMode::Gitlink),
            _ => None,
        }
    }
}

/// One parsed tree entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeEntry<'a> {
    /// The entry's mode.
    pub mode: EntryMode,
    /// The raw name (validated: non-empty, no `/`, printable ASCII).
    pub name: &'a [u8],
    /// The entry's object id.
    pub oid: [u8; 20],
}

/// Parse one tree entry at the front of `buf`, returning it and the
/// number of bytes consumed. `Err(Truncated)` on a short entry is
/// distinguishable from a malformed one; callers treat both as fatal.
pub fn parse_tree_entry(buf: &[u8]) -> Result<(TreeEntry<'_>, usize), ObjectError> {
    let space = buf
        .iter()
        .position(|&b| b == b' ')
        .ok_or(ObjectError::Truncated)?;
    let mode_bytes = buf.get(..space).ok_or(ObjectError::Truncated)?;
    if mode_bytes.is_empty() || mode_bytes.len() > 6 {
        return Err(ObjectError::BadMode);
    }
    let mut value = 0u32;
    for &byte in mode_bytes {
        if !(b'0'..=b'7').contains(&byte) {
            return Err(ObjectError::BadMode);
        }
        value = value
            .checked_mul(8)
            .and_then(|v| v.checked_add(u32::from(byte - b'0')))
            .ok_or(ObjectError::BadMode)?;
    }
    let mode = EntryMode::from_value(value).ok_or(ObjectError::BadMode)?;

    let rest = buf.get(space + 1..).ok_or(ObjectError::Truncated)?;
    let nul = rest
        .iter()
        .position(|&b| b == 0)
        .ok_or(ObjectError::Truncated)?;
    let name = rest.get(..nul).ok_or(ObjectError::Truncated)?;
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') {
        return Err(ObjectError::BadName);
    }
    if !name.iter().all(|&b| (0x20..=0x7e).contains(&b)) {
        return Err(ObjectError::BadName);
    }

    let oid_start = space
        .checked_add(1)
        .and_then(|v| v.checked_add(nul))
        .and_then(|v| v.checked_add(1))
        .ok_or(ObjectError::Truncated)?;
    let oid_end = oid_start.checked_add(20).ok_or(ObjectError::Truncated)?;
    let oid_bytes = buf.get(oid_start..oid_end).ok_or(ObjectError::Truncated)?;
    let mut oid = [0u8; 20];
    oid.copy_from_slice(oid_bytes);
    Ok((TreeEntry { mode, name, oid }, oid_end))
}

/// Parse the `tree <40-hex-oid>\n` header of a commit object and
/// return the root tree's id. Commits always start with this line
/// (git's commit format); anything else is [`ObjectError::BadCommit`].
pub fn parse_commit_tree(data: &[u8]) -> Result<[u8; 20], ObjectError> {
    let rest = data.strip_prefix(b"tree ").ok_or(ObjectError::BadCommit)?;
    let (hex, tail) = rest.split_at_checked(40).ok_or(ObjectError::BadCommit)?;
    let Some(tail) = tail.strip_prefix(b"\n") else {
        return Err(ObjectError::BadCommit);
    };
    // The line ends at the first LF; the rest of the commit (parents,
    // author, message) is not needed here.
    let _ = tail;
    let mut oid = [0u8; 20];
    for (slot, pair) in oid.iter_mut().zip(hex.as_chunks::<2>().0) {
        *slot = (hex_digit(pair[0]).ok_or(ObjectError::BadCommit)? << 4)
            | hex_digit(pair[1]).ok_or(ObjectError::BadCommit)?;
    }
    Ok(oid)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    const OID: [u8; 20] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0x01, 0x23, 0x45, 0x67,
    ];

    fn entry(mode: &[u8], name: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(mode);
        out.push(b' ');
        out.extend_from_slice(name);
        out.push(0);
        out.extend_from_slice(&OID);
        out
    }

    #[test]
    fn parses_all_five_modes() {
        let cases: [(&[u8], EntryMode); 5] = [
            (b"40000", EntryMode::Tree),
            (b"100644", EntryMode::Blob),
            (b"100755", EntryMode::Executable),
            (b"120000", EntryMode::Symlink),
            (b"160000", EntryMode::Gitlink),
        ];
        for (mode, want) in cases {
            let data = entry(mode, b"README.md");
            let (parsed, consumed) = parse_tree_entry(&data).expect("parses");
            assert_eq!(parsed.mode, want);
            assert_eq!(parsed.name, b"README.md");
            assert_eq!(parsed.oid, OID);
            assert_eq!(consumed, data.len());
        }
    }

    #[test]
    fn truncation_at_every_byte_boundary_is_refused() {
        let data = entry(b"100644", b"a");
        for cut in 0..data.len() {
            assert!(
                parse_tree_entry(&data[..cut]).is_err(),
                "accepted a {cut}-byte prefix"
            );
        }
        assert!(parse_tree_entry(&data).is_ok());
    }

    #[test]
    fn rejects_bad_modes() {
        for mode in [
            &b""[..],
            b"0",
            b"999999",
            b"10064x",
            b"100664",
            b"100600",
            b"7777777",
        ] {
            let data = entry(mode, b"f");
            assert_eq!(
                parse_tree_entry(&data).err(),
                Some(ObjectError::BadMode),
                "accepted mode {mode:?}"
            );
        }
    }

    #[test]
    fn rejects_bad_names() {
        for name in [&b""[..], b".", b"..", b"a/b", b"a\x01b", b"\xff"] {
            let data = entry(b"100644", name);
            assert_eq!(
                parse_tree_entry(&data).err(),
                Some(ObjectError::BadName),
                "accepted name {name:?}"
            );
        }
        // A space inside the name is legal in git and in our policy.
        let data = entry(b"100644", b"a b");
        assert_eq!(
            parse_tree_entry(&data).expect("parses").0.name,
            b"a b".as_slice()
        );
    }

    #[test]
    fn rejects_missing_separators() {
        let mut no_space = Vec::from(&b"100644"[..]);
        no_space.extend_from_slice(&OID);
        assert_eq!(
            parse_tree_entry(&no_space).err(),
            Some(ObjectError::Truncated)
        );
        let mut no_nul = Vec::from(&b"100644 name"[..]);
        no_nul.extend_from_slice(&OID);
        assert_eq!(
            parse_tree_entry(&no_nul).err(),
            Some(ObjectError::Truncated)
        );
        // NUL but only 19 oid bytes.
        let mut short_oid = Vec::from(&b"100644 name\0"[..]);
        short_oid.extend_from_slice(&OID[..19]);
        assert_eq!(
            parse_tree_entry(&short_oid).err(),
            Some(ObjectError::Truncated)
        );
    }

    #[test]
    fn commit_tree_header() {
        let hex = b"0123456789abcdef0123456789abcdef01234567";
        let mut commit = Vec::from(&b"tree "[..]);
        commit.extend_from_slice(hex);
        commit.push(b'\n');
        commit.extend_from_slice(b"parent deadbeef\n\nmessage\n");
        assert_eq!(
            parse_commit_tree(&commit).expect("parses"),
            [
                0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
                0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
            ]
        );
        for bad in [
            &b""[..],
            b"tree",
            b"tree ",
            b"tree 0123\n",
            b"tree 0123456789abcdef0123456789abcdef0123456\n", // 39 hex
            b"tree 0123456789abcdef0123456789abcdef0123456Z\n",
            b"tree 0123456789abcdef0123456789abcdef01234567", // no LF
            b"tree  0123456789abcdef0123456789abcdef01234567\n",
            b"Tree 0123456789abcdef0123456789abcdef01234567\n",
            b"tree 0123456789abcdef0123456789abcdef01234567\r\n",
        ] {
            assert_eq!(
                parse_commit_tree(bad).err(),
                Some(ObjectError::BadCommit),
                "accepted {bad:?}"
            );
        }
    }
}
