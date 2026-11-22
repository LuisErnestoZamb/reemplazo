//! Adversarial + golden-vector tests for the local object store.
//!
//! The constants asserted here are git's own: the empty blob
//! `e69de29…`, the empty tree `4b825dc…`, and `hello\n` →
//! `ce01362…` (checked with `git hash-object --stdin` while writing
//! this suite). Everything else is a round trip or a refusal: a parser
//! that accepts one byte of a truncated zlib stream, an unsorted index
//! or a 39-character ref fails the suite.

use git_store::{
    Error, IndexEntry, Kind, Mode, PathEntry, Signature, TreeEntry, base_name_compare,
    build_tree_hierarchy, decode_loose, decode_loose_with_limit, encode_commit, encode_head,
    encode_index, encode_loose, encode_loose_with_limit, encode_ref, encode_tree, hex_oid,
    loose_path, object_oid, parse_head, parse_index, parse_oid, parse_ref, valid_ref_name,
};
use miniz_oxide::deflate::compress_to_vec_zlib;
use sha1::{Digest, Sha1};
use std::string::String;
use std::vec::Vec;

const EMPTY_BLOB: [u8; 20] = [
    0xe6, 0x9d, 0xe2, 0x9b, 0xb2, 0xd1, 0xd6, 0x43, 0x4b, 0x8b, 0x29, 0xae, 0x77, 0x5a, 0xd8, 0xc2,
    0xe4, 0x8c, 0x53, 0x91,
];
const EMPTY_TREE: [u8; 20] = [
    0x4b, 0x82, 0x5d, 0xc6, 0x42, 0xcb, 0x6e, 0xb9, 0xa0, 0x60, 0xe5, 0x4b, 0xf8, 0xd6, 0x92, 0x88,
    0xfb, 0xee, 0x49, 0x04,
];
const HELLO_BLOB: [u8; 20] = [
    0xce, 0x01, 0x36, 0x25, 0x03, 0x0b, 0xa8, 0xdb, 0xa9, 0x06, 0xf7, 0x56, 0x96, 0x7f, 0x9e, 0x9c,
    0xa3, 0x94, 0x46, 0x4a,
];

fn hex(oid: &[u8; 20]) -> String {
    String::from_utf8(hex_oid(oid).to_vec()).expect("hex is ASCII")
}

fn oid(fill: u8) -> [u8; 20] {
    [fill; 20]
}

fn zlib(raw: &[u8]) -> Vec<u8> {
    compress_to_vec_zlib(raw, 1)
}

fn raw_index(entries: &[(&[u8], [u8; 20], u32)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DIRC");
    push_u32(&mut out, 2);
    push_u32(&mut out, u32::try_from(entries.len()).expect("entry count"));
    for (name, oid, mode) in entries {
        for value in [0u32, 0, 0, 0, 0, 0, *mode, 0, 0, 0] {
            push_u32(&mut out, value);
        }
        out.extend_from_slice(oid);
        out.extend_from_slice(
            &u16::try_from(name.len())
                .expect("name length")
                .to_be_bytes(),
        );
        out.extend_from_slice(name);
        let total = (62 + name.len() + 8) & !7;
        out.extend(std::iter::repeat_n(0u8, total - (62 + name.len())));
    }
    let mut hasher = Sha1::new();
    hasher.update(&out);
    out.extend_from_slice(hasher.finalize().as_slice());
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

// ---------------------------------------------------------------- object

#[test]
fn empty_blob_oid_is_gits_canonical_id() {
    assert_eq!(object_oid(Kind::Blob, b""), EMPTY_BLOB);
    assert_eq!(hex(&EMPTY_BLOB), "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391");
}

#[test]
fn empty_tree_oid_is_gits_canonical_id() {
    let bytes = encode_tree(&[]).expect("empty tree encodes");
    assert!(bytes.is_empty());
    assert_eq!(object_oid(Kind::Tree, &bytes), EMPTY_TREE);
    assert_eq!(hex(&EMPTY_TREE), "4b825dc642cb6eb9a060e54bf8d69288fbee4904");
}

#[test]
fn hello_blob_oid_matches_git_hash_object() {
    assert_eq!(object_oid(Kind::Blob, b"hello\n"), HELLO_BLOB);
}

#[test]
fn loose_object_round_trips_through_zlib() {
    for (kind, data) in [
        (Kind::Blob, &b"hello\n"[..]),
        (Kind::Blob, &b""[..]),
        (Kind::Tree, &b"100644 a\0xxxxxxxxxxxxxxxxxxxx"[..]),
        (Kind::Commit, &b"tree 0000\n"[..]),
        (Kind::Tag, &b"object 0000\ntype commit\n"[..]),
    ] {
        let loose = encode_loose(kind, data).expect("encodes");
        assert_eq!(loose.oid, object_oid(kind, data));
        let decoded = decode_loose(&loose.compressed).expect("decodes");
        assert_eq!(decoded.kind, kind);
        assert_eq!(decoded.oid, loose.oid);
        assert_eq!(decoded.data, data);
    }
}

#[test]
fn loose_object_is_zlib_framed_not_raw_content() {
    let loose = encode_loose(Kind::Blob, b"hello\n").expect("encodes");
    assert_eq!(loose.compressed.first().copied(), Some(0x78));
    assert!(!loose.compressed.starts_with(b"blob"));
}

#[test]
fn loose_path_is_objects_xx_rest() {
    let path = loose_path(&EMPTY_BLOB);
    let text = std::str::from_utf8(&path).expect("path is ASCII");
    assert_eq!(text, "objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391");
    assert_eq!(path.len(), git_store::LOOSE_PATH_LEN);
}

#[test]
fn decode_refuses_every_truncation_of_the_stream() {
    let loose =
        encode_loose(Kind::Blob, b"a payload long enough to need blocks........").expect("encodes");
    for cut in 0..loose.compressed.len() {
        assert!(
            decode_loose(&loose.compressed[..cut]).is_err(),
            "accepted a {cut}-byte zlib prefix"
        );
    }
    assert!(decode_loose(&loose.compressed).is_ok());
}

#[test]
fn decode_refuses_malformed_headers() {
    let cases: [(&[u8], Error); 8] = [
        (b"blob5\0hello", Error::BadHeader),
        (b"blob x\0hello", Error::BadHeader),
        (b"blob  5\0hello", Error::BadHeader),
        (b"blob 3\0hello", Error::SizeMismatch),
        (b"blob 6\0hello", Error::SizeMismatch),
        (b"widget 1\0x", Error::UnknownType),
        (b"blob 05\0hello", Error::BadHeader),
        (b"blob 5hello", Error::BadHeader),
    ];
    for (raw, want) in cases {
        let got = decode_loose(&zlib(raw)).err();
        assert_eq!(got, Some(want), "raw {raw:?}");
    }
}

#[test]
fn decode_refuses_non_zlib_bytes_and_empty_input() {
    assert_eq!(decode_loose(b"").err(), Some(Error::InputTooLarge));
    assert_eq!(
        decode_loose(b"this is not zlib").err(),
        Some(Error::CorruptZlib)
    );
}

#[test]
fn decode_refuses_output_past_the_caller_limit() {
    let mut raw = Vec::from(&b"blob 100\0"[..]);
    raw.extend_from_slice(&[b'x'; 100]);
    let compressed = zlib(&raw);
    assert_eq!(
        decode_loose_with_limit(&compressed, 10).err(),
        Some(Error::ObjectTooLarge)
    );
    assert!(decode_loose_with_limit(&compressed, 100).is_ok());
}

#[test]
fn encode_refuses_content_past_the_caller_limit() {
    assert_eq!(
        encode_loose_with_limit(Kind::Blob, b"12345", 4).err(),
        Some(Error::ObjectTooLarge)
    );
    assert!(encode_loose_with_limit(Kind::Blob, b"1234", 4).is_ok());
}

#[test]
fn parse_oid_is_strict_lowercase_40_hex() {
    let text = b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391";
    assert_eq!(parse_oid(text), Ok(EMPTY_BLOB));
    for bad in [
        &b""[..],
        &text[..39],
        &b"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391\n"[..],
        &b"E69DE29BB2D1D6434B8B29AE775AD8C2E48C5391"[..],
        &b"e69de29bb2d1d6434b8b29ae775ad8c2e48c539Z"[..],
    ] {
        assert_eq!(parse_oid(bad), Err(Error::BadOid), "{bad:?}");
    }
}

// ------------------------------------------------------------------ tree

#[test]
fn tree_ordering_file_beats_its_own_dotted_suffix() {
    // "foo" (blob) vs "foo.txt": at index 3, NUL < '.'.
    assert_eq!(
        base_name_compare(b"foo", false, b"foo.txt", false),
        core::cmp::Ordering::Less
    );
}

#[test]
fn tree_ordering_directory_loses_to_its_dotted_suffix() {
    // "foo" (dir) vs "foo.txt": at index 3, '/' (0x2F) > '.' (0x2E),
    // so git writes foo.txt *before* the foo/ subtree.
    assert_eq!(
        base_name_compare(b"foo", true, b"foo.txt", false),
        core::cmp::Ordering::Greater
    );
}

#[test]
fn tree_ordering_directory_beats_digit_suffix() {
    // "foo" (dir) vs "foo0": '/' (0x2F) < '0' (0x30).
    assert_eq!(
        base_name_compare(b"foo", true, b"foo0", false),
        core::cmp::Ordering::Less
    );
}

#[test]
fn tree_ordering_is_bytewise_and_antisymmetric() {
    let a = oid(1);
    let entries = [
        TreeEntry {
            mode: Mode::Blob,
            name: b"b",
            oid: a,
        },
        TreeEntry {
            mode: Mode::Blob,
            name: b"a",
            oid: a,
        },
    ];
    let bytes = encode_tree(&entries).expect("encodes");
    let mut want = Vec::new();
    want.extend_from_slice(b"100644 a\0");
    want.extend_from_slice(&a);
    want.extend_from_slice(b"100644 b\0");
    want.extend_from_slice(&a);
    assert_eq!(bytes, want);

    assert_eq!(
        base_name_compare(b"a", false, b"a", false),
        core::cmp::Ordering::Equal
    );
    assert_eq!(
        base_name_compare(b"a", false, b"b", false),
        core::cmp::Ordering::Less
    );
    assert_eq!(
        base_name_compare(b"b", false, b"a", false),
        core::cmp::Ordering::Greater
    );
}

#[test]
fn tree_modes_serialize_without_leading_zero() {
    let oid = oid(0xAB);
    let cases = [
        (Mode::Tree, &b"40000 "[..]),
        (Mode::Blob, &b"100644 "[..]),
        (Mode::Executable, &b"100755 "[..]),
        (Mode::Symlink, &b"120000 "[..]),
        (Mode::Gitlink, &b"160000 "[..]),
    ];
    for (index, (mode, prefix)) in cases.iter().enumerate() {
        let name = [b'a' + u8::try_from(index).expect("small")];
        let bytes = encode_tree(&[TreeEntry {
            mode: *mode,
            name: &name,
            oid,
        }])
        .expect("encodes");
        assert!(bytes.starts_with(prefix), "{mode:?}: {bytes:?}");
        assert_eq!(bytes[prefix.len() - 1], b' ');
        assert_eq!(
            bytes[prefix.len()],
            b'a' + u8::try_from(index).expect("small")
        );
    }
}

#[test]
fn encode_tree_refuses_duplicate_and_bad_names() {
    let oid = oid(7);
    let dup = [
        TreeEntry {
            mode: Mode::Blob,
            name: b"same",
            oid,
        },
        TreeEntry {
            mode: Mode::Executable,
            name: b"same",
            oid,
        },
    ];
    assert_eq!(encode_tree(&dup).err(), Some(Error::DuplicateEntry));

    for name in [&b""[..], b".", b"..", b"a/b", b"a\0b", &[b'x'; 256]] {
        let entries = [TreeEntry {
            mode: Mode::Blob,
            name,
            oid,
        }];
        assert_eq!(
            encode_tree(&entries).err(),
            Some(Error::BadName),
            "{name:?}"
        );
    }
}

#[test]
fn tree_names_may_be_non_ascii_and_sort_bytewise() {
    let oid = oid(3);
    let entries = [
        TreeEntry {
            mode: Mode::Blob,
            name: "é".as_bytes(),
            oid,
        },
        TreeEntry {
            mode: Mode::Blob,
            name: b"z",
            oid,
        },
    ];
    let bytes = encode_tree(&entries).expect("encodes");
    // 'z' (0x7A) sorts before 'é' (0xC3 0xA9).
    assert!(bytes.starts_with(b"100644 z\0"));
    assert!(bytes.windows(2).any(|w| w == "é".as_bytes()));
}

// ---------------------------------------------------------------- commit

#[test]
fn commit_bytes_are_exactly_gits_layout() {
    let tree = oid(0x11);
    let parent = oid(0x22);
    let author = Signature {
        name: b"A U Thor",
        email: b"author@example.com",
        epoch: 1_234_567_890,
    };
    let committer = Signature {
        name: b"C O Mitter",
        email: b"committer@example.com",
        epoch: 1_234_567_890,
    };
    let bytes =
        encode_commit(&tree, &[parent], &author, &committer, b"message\n").expect("encodes");
    let want = format!(
        "tree {}\nparent {}\nauthor A U Thor <author@example.com> 1234567890 +0000\ncommitter C O Mitter <committer@example.com> 1234567890 +0000\n\nmessage\n",
        hex(&tree),
        hex(&parent)
    );
    assert_eq!(String::from_utf8(bytes).expect("ASCII"), want);
}

#[test]
fn commit_without_parent_has_no_parent_line() {
    let tree = oid(1);
    let who = Signature {
        name: b"A",
        email: b"a@b",
        epoch: 0,
    };
    let bytes = encode_commit(&tree, &[], &who, &who, b"").expect("encodes");
    let text = String::from_utf8(bytes).expect("ASCII");
    assert!(!text.contains("parent "));
    assert!(text.ends_with(" +0000\n\n"));
}

#[test]
fn commit_message_trailing_newline_is_completed_once() {
    let tree = oid(1);
    let who = Signature {
        name: b"A",
        email: b"a@b",
        epoch: 1,
    };
    let with = encode_commit(&tree, &[], &who, &who, b"msg\n").expect("encodes");
    let without = encode_commit(&tree, &[], &who, &who, b"msg").expect("encodes");
    assert_eq!(with, without);
    assert!(with.ends_with(b"\n\nmsg\n"));
}

#[test]
fn commit_refuses_bad_identities_and_messages() {
    let tree = oid(1);
    let good = Signature {
        name: b"A",
        email: b"a@b",
        epoch: 1,
    };
    let bad = [
        Signature {
            name: b"",
            email: b"a@b",
            epoch: 1,
        },
        Signature {
            name: b"A",
            email: b"ab",
            epoch: 1,
        },
        Signature {
            name: b"A<",
            email: b"a@b",
            epoch: 1,
        },
        Signature {
            name: b"A",
            email: b"a>b",
            epoch: 1,
        },
        Signature {
            name: b"A\n",
            email: b"a@b",
            epoch: 1,
        },
        Signature {
            name: b"A",
            email: b"a@b",
            epoch: -1,
        },
    ];
    for who in bad {
        assert_eq!(
            encode_commit(&tree, &[], &who, &good, b"m\n").err(),
            Some(Error::BadIdent),
            "{who:?}"
        );
    }
    assert_eq!(
        encode_commit(&tree, &[], &good, &good, b"m\0\n").err(),
        Some(Error::BadMessage)
    );
}

#[test]
fn commit_refuses_more_parents_than_the_cap() {
    let tree = oid(1);
    let who = Signature {
        name: b"A",
        email: b"a@b",
        epoch: 1,
    };
    let parents = [oid(2); git_store::MAX_PARENTS + 1];
    assert_eq!(
        encode_commit(&tree, &parents, &who, &who, b"m\n").err(),
        Some(Error::TooManyParents)
    );
}

// ----------------------------------------------------------------- index

#[test]
fn index_entry_padding_follows_cache_entry_size() {
    let path = [b'a'; 32];
    for len in 1..=20usize {
        let name = path.get(..len).expect("in range");
        let entry = IndexEntry {
            path: name,
            oid: EMPTY_BLOB,
            mode: 0o100644,
            size: 1,
            mtime: 42,
        };
        let bytes = encode_index(&[entry]).expect("encodes");
        let want = 12 + ((62 + len + 8) & !7) + 20;
        assert_eq!(bytes.len(), want, "len {len}");
        let parsed = parse_index(&bytes).expect("parses");
        assert_eq!(parsed.entries.len(), 1);
        let record = &parsed.entries[0];
        assert_eq!(record.path, name);
        assert_eq!(record.oid, EMPTY_BLOB);
        assert_eq!(record.mode, 0o100644);
        assert_eq!(record.size, 1);
        assert_eq!(record.mtime, 42);
        assert_eq!(record.ctime, 42);
        // Every byte between the name and the next entry is NUL padding.
        for &byte in bytes
            .get(12 + 62 + len..12 + ((62 + len + 8) & !7))
            .expect("padding")
        {
            assert_eq!(byte, 0);
        }
    }
}

#[test]
fn index_round_trips_unsorted_input_in_path_order() {
    let entries = [
        IndexEntry {
            path: b"docs/hardware.md",
            oid: oid(3),
            mode: 0o100644,
            size: 61_928,
            mtime: 7,
        },
        IndexEntry {
            path: b"AGENTS.md",
            oid: oid(1),
            mode: 0o100644,
            size: 100,
            mtime: 7,
        },
        IndexEntry {
            path: b"README.md",
            oid: oid(2),
            mode: 0o100755,
            size: 200,
            mtime: 8,
        },
    ];
    let bytes = encode_index(&entries).expect("encodes");
    let parsed = parse_index(&bytes).expect("parses");
    let paths: Vec<&[u8]> = parsed
        .entries
        .iter()
        .map(|entry| entry.path.as_slice())
        .collect();
    let want: Vec<&[u8]> = [
        &b"AGENTS.md"[..],
        &b"README.md"[..],
        &b"docs/hardware.md"[..],
    ]
    .to_vec();
    assert_eq!(paths, want);
    assert_eq!(parsed.entries[1].mode, 0o100755);
}

#[test]
fn index_empty_is_header_plus_checksum() {
    let bytes = encode_index(&[]).expect("encodes");
    assert_eq!(bytes.len(), 32);
    let parsed = parse_index(&bytes).expect("parses");
    assert!(parsed.entries.is_empty());
}

#[test]
fn index_checksum_mismatch_is_refused() {
    let entry = IndexEntry {
        path: b"a",
        oid: EMPTY_BLOB,
        mode: 0o100644,
        size: 0,
        mtime: 0,
    };
    let mut bytes = encode_index(&[entry]).expect("encodes");
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    assert_eq!(parse_index(&bytes).err(), Some(Error::ChecksumMismatch));

    // Tampering with a content byte while keeping the checksum also
    // fails (it is a checksum, not a signature of intent).
    let mut bytes = encode_index(&[entry]).expect("encodes");
    bytes[12] ^= 0x01;
    assert_eq!(parse_index(&bytes).err(), Some(Error::ChecksumMismatch));
}

#[test]
fn index_signature_and_version_are_checked() {
    let entry = IndexEntry {
        path: b"a",
        oid: EMPTY_BLOB,
        mode: 0o100644,
        size: 0,
        mtime: 0,
    };
    let bytes = encode_index(&[entry]).expect("encodes");

    let mut bad_sig = bytes.clone();
    bad_sig[..4].copy_from_slice(b"DIRX");
    assert_eq!(parse_index(&bad_sig).err(), Some(Error::BadIndexSignature));

    for version in [1u32, 3, 4] {
        let mut bad = bytes.clone();
        bad[4..8].copy_from_slice(&version.to_be_bytes());
        assert_eq!(
            parse_index(&bad).err(),
            Some(Error::UnsupportedIndexVersion(version))
        );
    }
}

#[test]
fn index_refuses_every_truncation() {
    let entries = [
        IndexEntry {
            path: b"a",
            oid: oid(1),
            mode: 0o100644,
            size: 1,
            mtime: 1,
        },
        IndexEntry {
            path: b"dir/b",
            oid: oid(2),
            mode: 0o100644,
            size: 2,
            mtime: 2,
        },
    ];
    let bytes = encode_index(&entries).expect("encodes");
    for cut in 0..bytes.len() {
        assert!(parse_index(&bytes[..cut]).is_err(), "accepted {cut} bytes");
    }
    assert!(parse_index(&bytes).is_ok());
}

#[test]
fn index_refuses_absurd_counts_and_garbage_before_the_trailer() {
    let entry = IndexEntry {
        path: b"a",
        oid: EMPTY_BLOB,
        mode: 0o100644,
        size: 0,
        mtime: 0,
    };
    let bytes = encode_index(&[entry]).expect("encodes");

    let mut huge = bytes.clone();
    huge[8..12].copy_from_slice(&65_536u32.to_be_bytes());
    assert_eq!(parse_index(&huge).err(), Some(Error::BadIndex));

    let mut over_cap = bytes.clone();
    over_cap[8..12].copy_from_slice(&65_537u32.to_be_bytes());
    assert_eq!(parse_index(&over_cap).err(), Some(Error::TooManyEntries));

    let mut trailing = bytes;
    let trailer = trailing.split_off(trailing.len() - 20);
    trailing.push(0xAA);
    trailing.extend_from_slice(&trailer);
    // The old checksum now covers a byte that moved: recompute it to
    // isolate the "garbage before the trailer" refusal from a checksum
    // mismatch.
    let mut hasher = Sha1::new();
    hasher.update(&trailing[..trailing.len() - 20]);
    let digest = hasher.finalize();
    let len = trailing.len();
    trailing[len - 20..].copy_from_slice(digest.as_slice());
    assert_eq!(parse_index(&trailing).err(), Some(Error::BadIndex));
}

#[test]
fn index_refuses_unsorted_and_duplicate_entries() {
    let unsorted = raw_index(&[(b"b", oid(2), 0o100644), (b"a", oid(1), 0o100644)]);
    assert_eq!(parse_index(&unsorted).err(), Some(Error::UnsortedIndex));

    let duplicate = raw_index(&[(b"a", oid(1), 0o100644), (b"a", oid(2), 0o100644)]);
    assert_eq!(parse_index(&duplicate).err(), Some(Error::DuplicateEntry));
}

#[test]
fn index_refuses_bad_paths_and_modes() {
    for path in [&b""[..], b"/a", b"a/", b"a//b", b"a/../b", b"./a", b"a\0b"] {
        let entry = IndexEntry {
            path,
            oid: EMPTY_BLOB,
            mode: 0o100644,
            size: 0,
            mtime: 0,
        };
        assert_eq!(
            encode_index(&[entry]).err(),
            Some(Error::BadName),
            "{path:?}"
        );
    }
    let entry = IndexEntry {
        path: b"a",
        oid: EMPTY_BLOB,
        mode: 0o100664,
        size: 0,
        mtime: 0,
    };
    assert_eq!(encode_index(&[entry]).err(), Some(Error::BadMode));
}

#[test]
fn index_refuses_extended_flags_and_bad_padding() {
    let mut extended = raw_index(&[(b"a", EMPTY_BLOB, 0o100644)]);
    // Set the extended bit in the flags field (offset 12+60).
    extended[72] |= 0x40;
    let mut hasher = Sha1::new();
    hasher.update(&extended[..extended.len() - 20]);
    let digest = hasher.finalize();
    let len = extended.len();
    extended[len - 20..].copy_from_slice(digest.as_slice());
    assert_eq!(parse_index(&extended).err(), Some(Error::ExtendedFlags));

    let mut padding = raw_index(&[(b"a", EMPTY_BLOB, 0o100644)]);
    // The single NUL pad byte sits right after a 1-byte name.
    padding[12 + 62 + 1] = b'X';
    let mut hasher = Sha1::new();
    hasher.update(&padding[..padding.len() - 20]);
    let digest = hasher.finalize();
    let len = padding.len();
    padding[len - 20..].copy_from_slice(digest.as_slice());
    assert_eq!(parse_index(&padding).err(), Some(Error::BadIndex));
}

// ------------------------------------------------------------------ refs

#[test]
fn head_and_ref_round_trip() {
    assert_eq!(
        encode_head(b"main").expect("encodes"),
        b"ref: refs/heads/main\n".to_vec()
    );
    assert_eq!(
        parse_head(b"ref: refs/heads/main\n").expect("parses"),
        b"refs/heads/main"
    );
    assert_eq!(
        parse_head(b"ref: refs/heads/main").expect("no LF is accepted"),
        b"refs/heads/main"
    );

    let text = encode_ref(&EMPTY_BLOB);
    assert_eq!(text.len(), 41);
    assert_eq!(text[40], b'\n');
    assert_eq!(parse_ref(&text), Ok(EMPTY_BLOB));
    assert_eq!(parse_ref(&text[..40]), Ok(EMPTY_BLOB));
}

#[test]
fn head_refuses_bad_symbolic_refs() {
    for bad in [
        &b""[..],
        b"ref: ",
        b"refs/heads/main\n",
        b"ref: refs/heads/a..b\n",
        b"ref: refs/heads/.hidden\n",
        b"ref: refs/heads/x.lock\n",
        b"ref: refs/heads/a b\n",
        b"ref: refs/heads/main\nextra",
    ] {
        assert!(parse_head(bad).is_err(), "{bad:?}");
    }
    for branch in [&b""[..], b"a..b", b".x", b"x.lock", b"a b", b"a~1"] {
        assert_eq!(encode_head(branch).err(), Some(Error::BadRef), "{branch:?}");
    }
}

#[test]
fn ref_refuses_short_uppercase_and_trailing_bytes() {
    let good = encode_ref(&EMPTY_BLOB);
    let uppercase = good[..40].to_ascii_uppercase();
    let extended = [&good[..40], &b"x"[..]].concat();
    for bad in [&good[..39], uppercase.as_slice(), extended.as_slice()] {
        assert_eq!(parse_ref(bad), Err(Error::BadOid), "{bad:?}");
    }
}

#[test]
fn ref_name_rules_cover_the_documented_subset() {
    for good in [
        &b"refs/heads/main"[..],
        b"refs/heads/feature/x",
        b"refs/heads/a-b_c.1",
        b"refs/heads/rama-\xc3\xb1",
    ] {
        assert!(valid_ref_name(good), "{good:?}");
    }
    for bad in [
        &b""[..],
        b"/refs/heads/main",
        b"refs/heads/main/",
        b"refs//heads/main",
        b"refs/heads/..",
        b"refs/heads/a@{b",
        b"refs/heads/a\\b",
        b"refs/heads/a[b",
        b"@",
    ] {
        assert!(!valid_ref_name(bad), "{bad:?}");
    }
}

// ---------------------------------------------------------------- layout

fn empty_tree_oid() -> [u8; 20] {
    object_oid(Kind::Tree, &[])
}

#[test]
fn hierarchy_of_nothing_is_the_empty_tree() {
    let built = build_tree_hierarchy(&[]).expect("builds");
    assert_eq!(built.root, EMPTY_TREE);
    assert_eq!(built.trees.len(), 1);
    assert_eq!(built.trees[0].0, EMPTY_TREE);
    assert!(built.trees[0].1.is_empty());
}

#[test]
fn hierarchy_matches_a_hand_built_tree() {
    let a = oid(0xA1);
    let b = oid(0xB2);
    let entries = [
        PathEntry {
            path: b"dir/b",
            mode: Mode::Blob,
            oid: b,
        },
        PathEntry {
            path: b"a",
            mode: Mode::Blob,
            oid: a,
        },
    ];
    let built = build_tree_hierarchy(&entries).expect("builds");

    let subtree_bytes = encode_tree(&[TreeEntry {
        mode: Mode::Blob,
        name: b"b",
        oid: b,
    }])
    .expect("subtree");
    let subtree = object_oid(Kind::Tree, &subtree_bytes);
    let root_bytes = encode_tree(&[
        TreeEntry {
            mode: Mode::Tree,
            name: b"dir",
            oid: subtree,
        },
        TreeEntry {
            mode: Mode::Blob,
            name: b"a",
            oid: a,
        },
    ])
    .expect("root");

    assert_eq!(built.root, object_oid(Kind::Tree, &root_bytes));
    assert_eq!(built.trees.len(), 2);
    assert_eq!(built.trees[0], (subtree, subtree_bytes));
    assert_eq!(built.trees[1], (built.root, root_bytes));
    assert_ne!(built.root, empty_tree_oid());
}

#[test]
fn hierarchy_handles_executables_and_symlinks() {
    let entries = [
        PathEntry {
            path: b"run.sh",
            mode: Mode::Executable,
            oid: oid(1),
        },
        PathEntry {
            path: b"link",
            mode: Mode::Symlink,
            oid: oid(2),
        },
    ];
    let built = build_tree_hierarchy(&entries).expect("builds");
    let root_bytes = encode_tree(&[
        TreeEntry {
            mode: Mode::Symlink,
            name: b"link",
            oid: oid(2),
        },
        TreeEntry {
            mode: Mode::Executable,
            name: b"run.sh",
            oid: oid(1),
        },
    ])
    .expect("root");
    assert_eq!(built.root, object_oid(Kind::Tree, &root_bytes));
}

#[test]
fn hierarchy_refuses_bad_paths_duplicates_and_subtree_modes() {
    for path in [&b""[..], b"/a", b"a/", b"a//b", b"a/../b", b"./a", b"a\0b"] {
        let entry = [PathEntry {
            path,
            mode: Mode::Blob,
            oid: oid(1),
        }];
        assert!(build_tree_hierarchy(&entry).is_err(), "{path:?}");
    }

    let dup = [
        PathEntry {
            path: b"a",
            mode: Mode::Blob,
            oid: oid(1),
        },
        PathEntry {
            path: b"a",
            mode: Mode::Blob,
            oid: oid(2),
        },
    ];
    assert_eq!(
        build_tree_hierarchy(&dup).err(),
        Some(Error::DuplicateEntry)
    );

    let subtree = [PathEntry {
        path: b"a",
        mode: Mode::Tree,
        oid: oid(1),
    }];
    assert_eq!(build_tree_hierarchy(&subtree).err(), Some(Error::BadMode));
}

#[test]
fn hierarchy_nests_two_levels_bottom_up() {
    let c = oid(0xC3);
    let d = oid(0xD4);
    let entries = [
        PathEntry {
            path: b"a/b/c",
            mode: Mode::Blob,
            oid: c,
        },
        PathEntry {
            path: b"a/d",
            mode: Mode::Blob,
            oid: d,
        },
    ];
    let built = build_tree_hierarchy(&entries).expect("builds");

    let ab_bytes = encode_tree(&[TreeEntry {
        mode: Mode::Blob,
        name: b"c",
        oid: c,
    }])
    .expect("a/b");
    let ab = object_oid(Kind::Tree, &ab_bytes);
    let a_bytes = encode_tree(&[
        TreeEntry {
            mode: Mode::Tree,
            name: b"b",
            oid: ab,
        },
        TreeEntry {
            mode: Mode::Blob,
            name: b"d",
            oid: d,
        },
    ])
    .expect("a");
    let a = object_oid(Kind::Tree, &a_bytes);
    let root_bytes = encode_tree(&[TreeEntry {
        mode: Mode::Tree,
        name: b"a",
        oid: a,
    }])
    .expect("root");

    assert_eq!(built.trees.len(), 3);
    assert_eq!(built.trees[0], (ab, ab_bytes));
    assert_eq!(built.trees[1], (a, a_bytes));
    assert_eq!(
        built.trees[2],
        (object_oid(Kind::Tree, &root_bytes), root_bytes)
    );
    assert_eq!(built.root, built.trees[2].0);
    assert_ne!(built.root, oid(0xA5));
}

#[test]
fn hierarchy_rebuilding_is_deterministic() {
    let entries = [
        PathEntry {
            path: b"docs/hardware.md",
            mode: Mode::Blob,
            oid: oid(9),
        },
        PathEntry {
            path: b"README.md",
            mode: Mode::Blob,
            oid: oid(8),
        },
        PathEntry {
            path: b"kernel/src/main.rs",
            mode: Mode::Blob,
            oid: oid(7),
        },
    ];
    let first = build_tree_hierarchy(&entries).expect("builds");
    let second = build_tree_hierarchy(&entries).expect("builds");
    assert_eq!(first, second);
    assert_eq!(first.trees.len(), 4); // docs, kernel/src, kernel, root
}
