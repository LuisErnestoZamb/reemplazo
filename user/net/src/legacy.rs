//! Hito 3 + hito 4 proofs, carried into the hito-5 user ELF.
//!
//! The kernel's U1 loader has **one** capture slot (`hello`), so the
//! `smoke-user` ISO can only stage one user process at a time. This module
//! is the byte-for-byte proof body of `user/edit/src/main.rs` (console
//! round-trip, FS syscalls, gap-buffer save/read-back) without its REPL;
//! `main.rs` calls [`prove`] before its own network proof. Once the loader
//! gains a second capture slot these proofs can move back to `user/edit`
//! and run as a separate process — see the hito-5 report.

use userlib as sys;

const DOC_CAP: usize = 2048;
const LINE_CAP: usize = 256;
const STAT_CAP: usize = sys::STAT_LEN;
const DIR_CAP: usize = 8 * sys::DIRENT_LEN;

const DOC_PATH: &[u8] = b"/NOTES.TXT";
const DIR_PATH: &[u8] = b"/DOC";
const INSERT: &[u8] = b"user edit ok\n";

// Non-zero initial bytes keep every buffer in .data: an all-zero static
// lands in .bss and rust-lld emits a second R|W PT_LOAD that the U1
// loader refuses as `AlreadyMapped`.
static mut GAP: gapbuf::Gap<DOC_CAP> = gapbuf::Gap::new();
static mut EXPECTED: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut BACK: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut STAT_BUF: [u8; STAT_CAP] = [b' '; STAT_CAP];
static mut DIR_BUF: [u8; DIR_CAP] = [b' '; DIR_CAP];
static mut LINE: [u8; LINE_CAP] = [b' '; LINE_CAP];

/// Pure, fixed-capacity gap buffer: `front ++ gap ++ back`, with every
/// offset checked and no allocation. `copy_within` does the movement.
mod gapbuf {
    #![forbid(unsafe_code)]

    pub struct Gap<const N: usize> {
        data: [u8; N],
        gap_start: usize,
        gap_end: usize,
    }

    impl<const N: usize> Gap<N> {
        pub const fn new() -> Self {
            Self {
                data: [b' '; N],
                gap_start: 0,
                gap_end: N,
            }
        }

        pub fn load(&mut self, src: &[u8]) -> bool {
            if src.len() > N {
                return false;
            }
            self.data[..src.len()].copy_from_slice(src);
            self.gap_start = src.len();
            self.gap_end = N;
            true
        }

        pub fn len(&self) -> usize {
            self.gap_start + (N - self.gap_end)
        }

        fn move_gap(&mut self, pos: usize) -> bool {
            if pos > self.len() {
                return false;
            }
            if pos < self.gap_start {
                let n = self.gap_start - pos;
                self.data.copy_within(pos..self.gap_start, self.gap_end - n);
                self.gap_start = pos;
                self.gap_end -= n;
            } else if pos > self.gap_start {
                let n = pos - self.gap_start;
                self.data
                    .copy_within(self.gap_end..self.gap_end + n, self.gap_start);
                self.gap_start = pos;
                self.gap_end += n;
            }
            true
        }

        pub fn insert(&mut self, pos: usize, bytes: &[u8]) -> bool {
            if pos > self.len() || bytes.len() > N.saturating_sub(self.len()) {
                return false;
            }
            if bytes.len() > self.gap_end - self.gap_start && !self.move_gap(self.len()) {
                return false;
            }
            if !self.move_gap(pos) {
                return false;
            }
            self.data[pos..pos + bytes.len()].copy_from_slice(bytes);
            self.gap_start += bytes.len();
            true
        }

        pub fn copy_out(&self, out: &mut [u8]) -> usize {
            let n = self.len();
            if out.len() < n {
                return 0;
            }
            let front = self.gap_start;
            out[..front].copy_from_slice(&self.data[..front]);
            out[front..n].copy_from_slice(&self.data[self.gap_end..N]);
            n
        }
    }
}

// --- Static scratch accessors (single-threaded CPL3 process) -------------

fn gap() -> &'static mut gapbuf::Gap<DOC_CAP> {
    // SAFETY: single-threaded user process; this is the only reference
    // handed out to the scratch gap buffer and it is dropped before the
    // next syscall or accessor call.
    unsafe { &mut *core::ptr::addr_of_mut!(GAP) }
}

fn expected() -> &'static mut [u8; DOC_CAP] {
    // SAFETY: single-threaded, one live borrow at a time, no IRQ in CPL3
    // touches this process's statics.
    unsafe { &mut *core::ptr::addr_of_mut!(EXPECTED) }
}

fn back() -> &'static mut [u8; DOC_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(BACK) }
}

fn stat_buf() -> &'static mut [u8; STAT_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(STAT_BUF) }
}

fn dir_buf() -> &'static mut [u8; DIR_CAP] {
    // SAFETY: see `expected()`.
    unsafe { &mut *core::ptr::addr_of_mut!(DIR_BUF) }
}

fn line() -> &'static mut [u8; LINE_CAP] {
    // SAFETY: see `expected()`; the kernel's Read returns and drops its
    // borrow before this accessor is used again.
    unsafe { &mut *core::ptr::addr_of_mut!(LINE) }
}

fn die(what: &[u8]) -> ! {
    sys::write_str("FATAL: unet (legacy): ");
    let _ = sys::write(2, what);
    sys::write_str("\n");
    sys::exit(1)
}

fn expect(ok: bool, what: &[u8]) {
    if !ok {
        die(what);
    }
}

/// Console + VGA round-trip, FS syscalls and editor proof (U3 + U4), in
/// the same order as `user/edit`'s `main` so `smoke-user`'s marker chain
/// is unchanged.
pub fn prove() {
    match sys::console_dims() {
        Some((cols, rows)) if cols > 0 && rows > 0 => {}
        _ => die(b"no VGA console"),
    }
    const GLYPH: u8 = b'U';
    const ATTR: u8 = 0x1f;
    expect(
        sys::vga_put_cell(0, 0, GLYPH, ATTR) == 0
            && sys::vga_flush() == 0
            && sys::vga_peek(0, 0) == Some((GLYPH, ATTR)),
        b"VGA round-trip",
    );
    sys::write_str("USER_CONSOLE_OK\n");
    sys::write_str("USER_SHELL_OK\n");

    fs_proof();
    editor_proof();
    // Keep the REPL scratch buffer mapped (its VMA is the same `brk` as
    // every other static here) even though hito 5 exits before the REPL.
    let _ = line();
}

fn fs_proof() {
    expect(
        sys::fs_open(b"/../ETC/PASSWD", sys::O_RDONLY) == sys::EPERM,
        b"path escape was not refused",
    );
    expect(
        sys::fs_open(b"/NO-SUCH-FILE.TXT", sys::O_RDONLY) == sys::EINVAL,
        b"missing file opened",
    );

    let fd = sys::fs_open(DOC_PATH, sys::O_RDWR);
    expect(fd > 0, b"open /NOTES.TXT");
    let n = sys::fs_read(fd, back());
    expect(n > 0 && (n as usize) <= DOC_CAP, b"read /NOTES.TXT");
    let n = n as usize;

    let stat = stat_buf();
    expect(
        sys::fs_stat(fd, stat) == sys::STAT_LEN as i64,
        b"stat /NOTES.TXT",
    );
    expect(
        sys::stat_size(stat) == Some(n as u64),
        b"stat size != read bytes",
    );

    expect(sys::fs_read(0, back()) == sys::EINVAL, b"fd 0 accepted");
    expect(sys::fs_close(0) == sys::EINVAL, b"fd 0 closed");

    let dir = sys::fs_open(DIR_PATH, sys::O_RDONLY);
    expect(dir > 0, b"open /DOC");
    let dn = sys::fs_readdir(dir, dir_buf());
    expect(
        dn > 0 && (dn as usize) % sys::DIRENT_LEN == 0,
        b"readdir /DOC",
    );
    let mut name = [0u8; sys::DIRENT_NAME];
    let mut found = false;
    let mut at = 0usize;
    while at + sys::DIRENT_LEN <= dn as usize {
        if let Some(got) = sys::dirent_name(&dir_buf()[at..at + sys::DIRENT_LEN], &mut name)
            && eq(got, b"README.TXT")
        {
            found = true;
        }
        at += sys::DIRENT_LEN;
    }
    expect(found, b"readdir missing README.TXT");
    expect(sys::fs_close(dir) == 0, b"close /DOC");

    expect(sys::fs_close(fd) == 0, b"close /NOTES.TXT");
    sys::write_str("USER_FS_OK\n");
}

fn editor_proof() {
    let fd = sys::fs_open(DOC_PATH, sys::O_RDWR);
    expect(fd > 0, b"reopen /NOTES.TXT");
    let n = sys::fs_read(fd, back());
    expect(n > 0 && (n as usize) <= DOC_CAP, b"editor read");
    let n = n as usize;

    let buf = gap();
    expect(buf.load(&back()[..n]), b"gap load");
    let at = back()[..n]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(n, |i| i + 1);
    expect(buf.insert(at, INSERT), b"gap insert");
    let expected_len = buf.copy_out(expected());
    expect(expected_len == n + INSERT.len(), b"gap copy_out");

    expect(sys::fs_close(fd) == 0, b"close before save");
    let out = sys::fs_open(DOC_PATH, sys::O_WRONLY | sys::O_TRUNC);
    expect(out > 0, b"open for save");
    expect(
        sys::fs_write(out, &expected()[..expected_len]) == expected_len as i64,
        b"save write",
    );
    expect(sys::fs_close(out) == 0, b"close after save");

    let verify = sys::fs_open(DOC_PATH, sys::O_RDONLY);
    expect(verify > 0, b"reopen for verify");
    let read_back = sys::fs_read(verify, back());
    expect(read_back == expected_len as i64, b"read-back length");
    expect(
        eq(&back()[..expected_len], &expected()[..expected_len]),
        b"read-back bytes differ",
    );
    let stat = stat_buf();
    expect(
        sys::fs_stat(verify, stat) == sys::STAT_LEN as i64
            && sys::stat_size(stat) == Some(expected_len as u64),
        b"read-back stat",
    );
    expect(sys::fs_close(verify) == 0, b"close after verify");
    sys::write_str("USER_EDITOR_OK\n");
}

fn eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
}
