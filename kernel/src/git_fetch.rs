//! `git fetch --depth=1` + checkout over smart HTTP — milestone G3 of
//! docs/git-ssh-deps.md (the follow-up to G2's `ls-remote`).
//!
//! Wire format (protocol v0, **no side-band**):
//!
//! - [pack-protocol §Packfile Negotiation](https://git-scm.com/docs/pack-protocol#_packfile_negotiation):
//!   the client sends `want <oid> <capabilities>\n`, a `deepen 1\n`
//!   line (shallow clone), a flush-pkt, then `done\n` and a final
//!   flush-pkt. We ask only for `ofs-delta` and `shallow`; **not**
//!   `side-band`/`side-band-64k`, so the server's answer is plain
//!   pkt-lines followed by the raw packfile bytes.
//! - [http-protocol](https://git-scm.com/docs/http-protocol): the
//!   request is `POST <repo>/git-upload-pack`, media type
//!   `application/x-git-upload-pack-request`, and the reply must be
//!   `application/x-git-upload-pack-result`.
//! - Answer: zero or more `shallow <oid>` pkt-lines, a flush, `NAK`,
//!   then `PACK` … to the end of the body (no pkt-line framing once
//!   side-band is off).
//!
//! The pack decoder (header, zlib streams, OFS/REF deltas, trailer
//! SHA-1, index) is the `git-pack` crate; the pkt-line decoder is
//! `git-pktline`; tree/commit object parsing (`<mode> <name> NUL
//! <oid>`, `tree <hex>\n`) is `git-pack::tree`, which carries the
//! adversarial tests (the kernel cannot be host-tested). This module
//! only assembles the want list, frames the reply, walks the fetched
//! commit's tree iteratively and — on a machine with a FAT16 disk —
//! checks the representable blobs out.
//!
//! # Bounds (the kernel heap is 16 MiB)
//!
//! - response body ≤ [`RESPONSE_CAP`] (2 MiB pack + pkt overhead);
//! - pack object count ≤ [`MAX_OBJECTS`] *before* `git-pack` allocates
//!   (the decoder's own cap only rejects counts the input cannot
//!   hold);
//! - decompressed pack output ≤ [`MAX_TOTAL_OUTPUT`], one object
//!   ≤ [`MAX_OBJECT_SIZE`] (both handed to `git-pack`);
//! - tree walk: depth ≤ [`MAX_DEPTH`], entries ≤ [`MAX_TREE_ENTRIES`],
//!   files ≤ [`MAX_FILES`], path ≤ [`PATH_CAP`], blob ≤
//!   [`MAX_OBJECT_SIZE`].
//!
//! Every wire-derived string is either validated (hex ids, the tree
//! modes) or sanitized before it reaches the serial log, exactly like
//! `git.rs`.
//!
//! # Checkout scope (FS3/G4)
//!
//! The kernel's FAT16 writer now has `mkdir` and LFN writes, so the
//! checkout is **full**: every regular blob in the depth-1 tree is
//! written to the volume, creating directories as needed and storing
//! names longer than 8.3 behind LFN chains (`fat::write_file_all`).
//! Symlinks and gitlink/submodule entries are still skipped and counted
//! (a symlink is not a file yet; a submodule's objects are not in this
//! pack). The proof re-mounts from scratch, asserts the file **count**
//! matches what the walk saw (a silent skip fails), reads back
//! `README.md` and the nested `docs/hardware.md` byte-exact, and
//! checks a content fragment in each. `.git/objects`/refs/HEAD remain
//! G4/G5 work: the decoded pack and its in-memory index are
//! proof-of-fetch, not a clone layout.

use crate::fs;
use crate::git::sanitize;
use crate::netstack::Stack;
use crate::tls;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::ptr::addr_of_mut;
use git_pack::{Kind, Limits, PackIndex};
use git_pktline::{Pkt, Step, decode, encode_data, encode_flush};
use smoltcp::wire::Ipv4Address;

/// Local port of the fetch connection (plain HTTP 49152, robots TLS
/// 49160, git TLS 49161, ssh 49162, AI 49163, browser 49164/49165,
/// **fetch 49166**): TIME-WAIT forbids reusing a socket for 10 s.
const LOCAL_PORT: u16 = 49166;
/// SNI + certificate hostname (the pinned root and the G2 single host).
const HOST: &str = "github.com";
/// Same public repo as G2's `ls-remote`.
const PATH: &str = "/LuisErnestoZamb/reemplazo.git/git-upload-pack";
/// Request media type (http-protocol: the POST body is the
/// `git-upload-pack` request stream).
const REQ_CT: &str = "application/x-git-upload-pack-request";
/// http-protocol requires this media type on the reply; asserting it
/// proves the bytes are a pack answer, not an HTML error page.
const EXPECT_CT: &[u8] = b"application/x-git-upload-pack-result";
/// Raw-pack cap (this repo's depth-1 pack is ~540 KiB; 2 MiB leaves
/// ~4× headroom and keeps the static response buffer, the decoded
/// objects and the heap well inside 16 MiB).
const PACK_CAP: usize = 2 * 1024 * 1024;
/// Response-body cap: the pack plus the small pkt-line section.
const RESPONSE_CAP: usize = PACK_CAP + 8 * 1024;
/// Decompressed pack output cap handed to `git-pack` (objects held in
/// RAM while deltas resolve).
const MAX_TOTAL_OUTPUT: usize = 8 * 1024 * 1024;
/// Per-object cap handed to `git-pack`.
const MAX_OBJECT_SIZE: usize = 4 * 1024 * 1024;
/// Object-count cap checked on the pack header before decoding: bounds
/// `git-pack`'s entry vector and this module's oid map (the decoder's
/// own `AbsurdObjectCount` only rejects counts the file cannot hold).
const MAX_OBJECTS: u64 = 10_000;
/// Tree nesting cap (hostile trees cannot recurse — the walker is
/// iterative anyway; this bounds the frame vector and path buffer).
const MAX_DEPTH: usize = 16;
/// Total tree entries visited (files + directories + skipped links).
const MAX_TREE_ENTRIES: usize = 4096;
/// Regular files accepted from the tree.
const MAX_FILES: usize = 1024;
/// Full path length cap (POSIX-ish; also bounds the walker's buffer).
const PATH_CAP: usize = 255;
/// Read-back buffer for the checkout proof (`docs/hardware.md` is
/// ~60 KiB; the cap makes a runaway file fail loudly instead of
/// truncating).
const READ_BACK_CAP: usize = 128 * 1024;
/// Printable-ASCII sanitizer buffer for logged tree paths.
const SANITIZE_CAP: usize = 128;
/// The smoke requires a real tree, not a one-file toy.
const MIN_FILES: usize = 20;
/// The checkout proof requires the *whole* depth-1 tree (this repo has
/// 106 files in 49 directories); a silent skip regression fails here.
const MIN_CHECKOUT_FILES: usize = 100;
const MIN_CHECKOUT_DIRS: usize = 45;
/// A nested file (three path components) that the checkout proof reads
/// back byte-exact — it exists only if the directory tree was created.
const NESTED_PROOF_PATH: &str = "docs/hardware.md";
/// A fragment that must appear in the nested proof file (the target
/// CPU's model number, stable across rewrites of the document).
const NESTED_PROOF_FRAGMENT: &[u8] = b"T7400";
/// A fragment that must appear in the checked-out `README.md`.
const README_FRAGMENT: &[u8] = b"AGPL";

/// Response storage (the `READ_STORAGE` idiom of `tls.rs`/`git.rs`):
/// written once by [`fetch`] on a single core; IRQ0 never touches it.
static mut RESPONSE: [u8; RESPONSE_CAP] = [0; RESPONSE_CAP];
/// Checkout read-back buffer (single use, same reasoning).
static mut READ_BACK: [u8; READ_BACK_CAP] = [0; READ_BACK_CAP];

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: git: {msg}");
    crate::halt()
}

/// Fetch `head` with `deepen 1`, decode the pack, walk the commit's
/// tree, print the summary + `GIT_FETCH_OK`, then — only when a disk
/// is attached — check the representable blobs out and print
/// `GIT_CHECKOUT_OK`. Without a disk nothing extra is printed, so the
/// diskless main smoke's marker chain is untouched.
///
/// `head` is the oid G2 parsed out of the advertisement (`HEAD`).
pub fn fetch(
    stack: &mut Stack,
    ip: Ipv4Address,
    head: [u8; 20],
    drive: Option<&crate::ata::Drive>,
) {
    // 1. The want/deepen/done request (see the module docs for the
    //    exact v0 grammar).
    let mut request = [0u8; 256];
    let Some(request_len) = want_request(&head, &mut request) else {
        fatal("upload-pack request does not fit the buffer");
    };

    // 2. POST it over TLS. `tls_post` asserts 200 +
    //    `application/x-git-upload-pack-result` and caps the body;
    //    anything outside that is `FATAL: git: …`.
    let handle = stack.tcp8_handle;
    let tls = tls::tls_open(stack, handle, ip, HOST, LOCAL_PORT);
    // SAFETY: single-use static (see `RESPONSE`).
    let response = unsafe { &mut *addr_of_mut!(RESPONSE) };
    let (status, body_total) = tls::tls_post(
        tls,
        HOST,
        tls::Post {
            path: PATH,
            content_type: REQ_CT,
            body: &request[..request_len],
        },
        EXPECT_CT,
        RESPONSE_CAP,
        response,
    );
    debug_assert_eq!(status, 200); // tls_post already refuses anything else
    if body_total > response.len() {
        fatal("response exceeds the response bound");
    }
    let body = &response[..body_total];

    // 3. pkt-line section (shallow/unshallow lines, flush, NAK), then
    //    the raw pack.
    let (shallow, pack) = parse_upload_pack(body);
    serial_println!(
        "git: fetch: upload-pack reply {} bytes, {} shallow line(s), pack {} bytes",
        body.len(),
        shallow,
        pack.len()
    );
    if pack.len() > PACK_CAP {
        fatal("pack exceeds the pack bound");
    }

    // 4. Decode: header count bound first (before `git-pack` builds
    //    its per-object tables), then the full decode with explicit
    //    limits. `git-pack` verifies the trailer SHA-1 and refuses
    //    thin packs — nothing is trusted on a best-effort basis.
    match git_pack::parse_header(pack) {
        git_pack::HeaderStep::Done { count } if u64::from(count) <= MAX_OBJECTS => {}
        git_pack::HeaderStep::Done { .. } => fatal("pack declares too many objects"),
        git_pack::HeaderStep::Failed(e) => {
            serial_println!("FATAL: git: bad pack header: {e:?}");
            crate::halt();
        }
        git_pack::HeaderStep::Incomplete => fatal("pack header truncated"),
    }
    let limits = Limits {
        max_object_size: MAX_OBJECT_SIZE,
        max_total_output: MAX_TOTAL_OUTPUT,
        max_delta_chain: 50,
    };
    let (objects, index): (Vec<git_pack::Object>, PackIndex) =
        match git_pack::decode_with_limits_and_index(pack, &limits) {
            Ok(decoded) => decoded,
            Err(e) => {
                serial_println!("FATAL: git: pack refused: {e:?}");
                crate::halt();
            }
        };
    if index.len() != objects.len() {
        fatal("pack index does not cover every object");
    }
    serial_println!(
        "git: pack: {} objects, {} index entries",
        objects.len(),
        index.len()
    );

    // 5. oid → object index (the walk needs random access; the pack's
    //    own order is irrelevant).
    let mut by_oid: BTreeMap<[u8; 20], usize> = BTreeMap::new();
    for (i, object) in objects.iter().enumerate() {
        by_oid.insert(object.oid(), i);
    }

    // 6. commit → tree → files (iterative; see `walk`).
    let tree_oid = commit_tree(&objects, &by_oid, &head);
    let mut files: Vec<(Vec<u8>, &[u8])> = Vec::new();
    let walk = walk(&objects, &by_oid, &tree_oid, &mut files);

    serial_println!(
        "git: tree: {} files in {} dirs, {} symlinks/submodules skipped, {} entries",
        walk.files,
        walk.dirs,
        walk.skipped,
        walk.entries
    );
    if walk.files < MIN_FILES {
        fatal("fetched tree has too few files (truncated or wrong pack?)");
    }
    if !walk.readme || !walk.agents {
        fatal("fetched tree lacks README.md or AGENTS.md");
    }
    if files.len() != walk.files {
        fatal("tree walk collected fewer blobs than it counted");
    }
    // A couple of sanitized paths: enough to see it is the real repo,
    // never a giant log (and never raw wire bytes).
    let mut path_buf = [0u8; SANITIZE_CAP];
    for sample in walk.samples.iter().flatten() {
        let name = sanitize(sample, &mut path_buf);
        serial_println!("git: file: {name}");
    }

    serial_println!("GIT_FETCH_OK"); // machine-checked by `cargo xtask smoke`

    // 7. Checkout — disk only. Without a drive this whole block is
    //    skipped (the diskless smoke); the handle comes from the boot
    //    probe, so `BLK_OK` is never printed a second time.
    if let Some(drive) = drive {
        checkout(drive, &files, &walk);
    }
}

/// Check out the **whole** fetched tree and prove the round trip:
/// write every blob (directories created as needed), re-mount from
/// scratch, read `README.md` and the nested [`NESTED_PROOF_PATH`] back
/// byte-exact with a content fragment each, assert the file count (a
/// silently skipped blob fails loudly), then print `GIT_CHECKOUT_OK`
/// (smoke-install).
fn checkout(drive: &crate::ata::Drive, files: &[(Vec<u8>, &[u8])], walk: &Walk) {
    if walk.files < MIN_CHECKOUT_FILES || walk.dirs < MIN_CHECKOUT_DIRS {
        fatal("checkout: fetched tree is smaller than the full checkout requires");
    }
    let (written, skipped) = fs::checkout_tree(drive, files);
    serial_println!(
        "git: checkout: {written} of {} file(s) written in {} dirs, {skipped} skipped",
        files.len(),
        walk.dirs
    );
    if skipped != 0 || written != files.len() {
        fatal("checkout: not every fetched blob reached the volume");
    }

    // SAFETY: single-use static (see `READ_BACK`).
    let read_back = unsafe { &mut *addr_of_mut!(READ_BACK) };

    // The fetched README.md bytes are the reference; the read-back is
    // served by a *fresh* mount inside `fs::read_back`.
    let Some(readme) = files
        .iter()
        .find(|(name, _)| name.as_slice() == b"README.md")
    else {
        fatal("checkout: fetched tree has no root README.md");
    };
    if readme.1.len() > READ_BACK_CAP {
        fatal("checkout: README.md exceeds the read-back buffer");
    }
    let n = fs::read_back(drive, "/README.md", read_back);
    if n != readme.1.len() || read_back[..n] != *readme.1 {
        fatal("checkout: README.md read back does not match the fetched blob");
    }
    if !contains(&read_back[..n], README_FRAGMENT) {
        fatal("checkout: README.md read back lacks the AGPL fragment");
    }
    serial_println!(
        "git: checkout: README.md {} bytes verified (AGPL fragment present)",
        n
    );

    // The nested proof: a file that exists only if `fat::create_dir_all`
    // built `docs/` and the blob was written inside it.
    let Some(nested) = files
        .iter()
        .find(|(name, _)| name.as_slice() == NESTED_PROOF_PATH.as_bytes())
    else {
        fatal("checkout: fetched tree has no docs/hardware.md");
    };
    if nested.1.len() > READ_BACK_CAP {
        fatal("checkout: docs/hardware.md exceeds the read-back buffer");
    }
    let n = fs::read_back(drive, "/docs/hardware.md", read_back);
    if n != nested.1.len() || read_back[..n] != *nested.1 {
        fatal("checkout: docs/hardware.md read back does not match the fetched blob");
    }
    if !contains(&read_back[..n], NESTED_PROOF_FRAGMENT) {
        fatal("checkout: docs/hardware.md read back lacks the T7400 fragment");
    }
    serial_println!(
        "git: checkout: docs/hardware.md {} bytes verified (nested directory tree)",
        n
    );

    serial_println!("GIT_CHECKOUT_OK"); // machine-checked by `cargo xtask smoke-install`
}

/// Build the v0 upload-pack request:
/// `want <oid> ofs-delta shallow\n` (caps on the first want),
/// `deepen 1\n`, flush, `done\n`, flush.
fn want_request(head: &[u8; 20], out: &mut [u8]) -> Option<usize> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut oid = [0u8; 40];
    let (pairs, _) = oid.as_chunks_mut::<2>();
    for (pair, &byte) in pairs.iter_mut().zip(head) {
        pair[0] = HEX[usize::from(byte >> 4)];
        pair[1] = HEX[usize::from(byte & 0x0F)];
    }
    let mut line = [0u8; 64];
    let line_len = 5 + 40 + 19; // "want " + oid + " ofs-delta shallow\n"
    line.get_mut(..5)?.copy_from_slice(b"want ");
    line.get_mut(5..45)?.copy_from_slice(&oid);
    line.get_mut(45..line_len)?
        .copy_from_slice(b" ofs-delta shallow\n");

    let mut off = encode_data(line.get(..line_len)?, out)?;
    off += encode_data(b"deepen 1\n", out.get_mut(off..)?)?;
    off += encode_flush(out.get_mut(off..)?)?;
    off += encode_data(b"done\n", out.get_mut(off..)?)?;
    off += encode_flush(out.get_mut(off..)?)?;
    Some(off)
}

/// Split the upload-pack reply into `(shallow-line count, pack bytes)`.
/// Accepts `shallow`/`unshallow` lines (bounded), flush control lines
/// and the terminating `NAK`; anything else is a protocol violation
/// and fatal — never skipped.
fn parse_upload_pack(body: &[u8]) -> (usize, &[u8]) {
    let mut pos = 0usize;
    let mut shallow = 0usize;
    loop {
        let slice = match body.get(pos..) {
            Some(s) => s,
            None => fatal("upload-pack reply ended before NAK"),
        };
        let (consumed, pkt) = match decode(slice) {
            Step::Incomplete => fatal("upload-pack reply truncated in the pkt-line section"),
            Step::Failed(e) => {
                serial_println!("FATAL: git: bad pkt-line in upload-pack reply: {e:?}");
                crate::halt();
            }
            Step::Done { consumed, pkt } => (consumed, pkt),
        };
        match pkt {
            Pkt::Flush => {}
            Pkt::Delim => fatal("upload-pack v0 reply carries a v1 delimiter"),
            Pkt::Data(line) => {
                let shallow_oid = line
                    .strip_prefix(b"shallow ")
                    .or_else(|| line.strip_prefix(b"unshallow "));
                if let Some(rest) = shallow_oid {
                    // git writes these without the trailing LF
                    // (`packet_writer_write("shallow %s")`), so accept
                    // both forms but demand a real 40-hex object id.
                    let oid = rest.strip_suffix(b"\n").unwrap_or(rest);
                    if oid.len() != 40 || !oid.iter().all(|b| b.is_ascii_hexdigit()) {
                        fatal("malformed shallow line in upload-pack reply");
                    }
                    shallow += 1;
                    if shallow > 64 {
                        fatal("upload-pack reply carries too many shallow lines");
                    }
                } else if line == b"NAK\n" {
                    let start = match pos.checked_add(consumed) {
                        Some(start) => start,
                        None => fatal("upload-pack reply offset overflow"),
                    };
                    let pack = match body.get(start..) {
                        Some(pack) => pack,
                        None => fatal("upload-pack reply ended after NAK"),
                    };
                    if !pack.starts_with(git_pack::PACK_MAGIC.as_slice()) {
                        fatal("upload-pack reply after NAK is not a packfile");
                    }
                    return (shallow, pack);
                } else if line.starts_with(b"ERR ") {
                    fatal("server refused the fetch (ERR pkt-line)");
                } else {
                    fatal("unexpected pkt-line before NAK in upload-pack reply");
                }
            }
        }
        pos = match pos.checked_add(consumed) {
            Some(pos) => pos,
            None => fatal("upload-pack reply offset overflow"),
        };
    }
}

/// Resolve `head` to its commit and return the root tree id parsed by
/// `git-pack`'s host-tested commit-header parser (`tree <40
/// hex>\n`). Any other layout is refused — a commit without a tree is
/// not a commit.
fn commit_tree(
    objects: &[git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
    head: &[u8; 20],
) -> [u8; 20] {
    let Some(&idx) = by_oid.get(head) else {
        fatal("fetched pack does not contain the advertised HEAD commit");
    };
    let Some(commit) = objects.get(idx) else {
        fatal("commit object index out of range");
    };
    if commit.kind != Kind::Commit {
        fatal("advertised HEAD is not a commit object");
    }
    match git_pack::parse_commit_tree(&commit.data) {
        Ok(tree) => tree,
        Err(e) => {
            serial_println!("FATAL: git: malformed commit object: {e:?}");
            crate::halt();
        }
    }
}

/// Counters + the proof flags from one tree walk.
struct Walk {
    files: usize,
    dirs: usize,
    skipped: usize,
    entries: usize,
    readme: bool,
    agents: bool,
    samples: [Option<Vec<u8>>; 2],
}

/// One depth-first frame: the tree object and where to resume reading
/// it, plus the path length to restore when it is popped.
struct Frame {
    tree: usize,
    next: usize,
    prefix: usize,
}

/// Walk the fetched tree **iteratively** (an explicit frame stack, so
/// a hostile 16-level tree cannot smash the kernel stack), resolving
/// blobs through `by_oid`. Every regular file is collected in `files`
/// as its full relative path (bytes, `Vec`) plus the blob — the
/// checkout's input; symlinks and gitlinks are counted only.
fn walk<'a>(
    objects: &'a [git_pack::Object],
    by_oid: &BTreeMap<[u8; 20], usize>,
    root_tree: &[u8; 20],
    files: &mut Vec<(Vec<u8>, &'a [u8])>,
) -> Walk {
    let mut stats = Walk {
        files: 0,
        dirs: 0,
        skipped: 0,
        entries: 0,
        readme: false,
        agents: false,
        samples: [None, None],
    };
    let Some(root_idx) = by_oid.get(root_tree).copied() else {
        fatal("root tree is not in the fetched pack");
    };
    let mut frames: Vec<Frame> = Vec::new();
    frames.push(Frame {
        tree: root_idx,
        next: 0,
        prefix: 0,
    });
    let mut path: Vec<u8> = Vec::new();

    while let Some(frame) = frames.last_mut() {
        let tree_data = match objects.get(frame.tree) {
            Some(tree) if tree.kind == Kind::Tree => tree.data.as_slice(),
            Some(_) => fatal("tree entry points at a non-tree object"),
            None => fatal("tree object index out of range"),
        };
        if frame.next >= tree_data.len() {
            let popped = frames.pop();
            if let Some(popped) = popped {
                path.truncate(popped.prefix);
            }
            continue;
        }
        let entry_start = frame.next;
        match git_pack::parse_tree_entry(&tree_data[entry_start..]) {
            Ok((entry, consumed)) => {
                frame.next = match entry_start.checked_add(consumed) {
                    Some(next) => next,
                    None => fatal("tree entry offset overflow"),
                };
                stats.entries += 1;
                if stats.entries > MAX_TREE_ENTRIES {
                    fatal("tree exceeds the entry bound");
                }
                match entry.mode {
                    git_pack::EntryMode::Tree => {
                        stats.dirs += 1;
                        let Some(&child) = by_oid.get(&entry.oid) else {
                            fatal("tree entry points at an object absent from the pack");
                        };
                        if frames.len() >= MAX_DEPTH {
                            fatal("tree exceeds the depth bound");
                        }
                        if path.len() + entry.name.len() + 1 > PATH_CAP {
                            fatal("tree path exceeds the path bound");
                        }
                        let prefix = path.len();
                        path.extend_from_slice(entry.name);
                        path.push(b'/');
                        frames.push(Frame {
                            tree: child,
                            next: 0,
                            prefix,
                        });
                    }
                    git_pack::EntryMode::Blob | git_pack::EntryMode::Executable => {
                        stats.files += 1;
                        if stats.files > MAX_FILES {
                            fatal("tree exceeds the file bound");
                        }
                        path.extend_from_slice(entry.name);
                        if path.len() > PATH_CAP {
                            fatal("tree path exceeds the path bound");
                        }
                        let Some(&blob_idx) = by_oid.get(&entry.oid) else {
                            fatal("blob is absent from the fetched pack");
                        };
                        let Some(blob) = objects.get(blob_idx) else {
                            fatal("blob object index out of range");
                        };
                        if blob.kind != Kind::Blob {
                            fatal("tree entry points at a non-blob object");
                        }
                        if path == b"README.md" {
                            stats.readme = true;
                        } else if path == b"AGENTS.md" {
                            stats.agents = true;
                        }
                        // The whole tree is checked out (directories are
                        // created by `fat::write_file_all`); the path is
                        // copied because `path` is reused for the next
                        // entry.
                        files.push((path.clone(), blob.data.as_slice()));
                        if stats.samples[0].is_none() {
                            stats.samples[0] = Some(path.clone());
                        } else if stats.samples[1].is_none() && path != b"README.md" {
                            stats.samples[1] = Some(path.clone());
                        }
                        path.truncate(path.len() - entry.name.len());
                    }
                    // Symlink and gitlink/submodule: not checked out in
                    // v1 — counted, never guessed.
                    git_pack::EntryMode::Symlink | git_pack::EntryMode::Gitlink => {
                        stats.skipped += 1;
                    }
                }
            }
            Err(e) => {
                serial_println!("FATAL: git: malformed tree entry: {e:?}");
                crate::halt();
            }
        }
    }
    stats
}

/// `needle` occurs in `haystack` (bounded substring search — used for
/// the AGPL fragment, no `memchr` dependency).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack.len() >= needle.len()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
