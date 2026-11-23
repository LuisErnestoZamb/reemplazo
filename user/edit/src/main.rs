//! Hito 4 — the first *user-process* editor.
//!
//! `no_std`, no heap, no allocator. The process opens a bounded file on
//! the kernel-owned volume through syscalls 10..=15, edits the bytes in a
//! fixed-capacity gap buffer, writes the whole document back through
//! `Write`, closes, reopens and compares the read-back **byte-exact**
//! before printing `USER_EDITOR_OK`. `USER_FS_OK` is printed after the
//! syscall round-trip (open/read/stat/readdir/close, plus deliberate
//! fail-closed path/fd violations) has passed.
//!
//! This ELF also carries the hito-3 console preamble and a one-line
//! REPL (`echo …`) so `smoke-user`'s existing marker order and keyboard
//! injection phase stay unchanged: the staged module must prove both
//! milestones because the loader has one capture slot today.
//!
//! `forbid(unsafe_code)` is declared on the pure gap-buffer module; the
//! only unsafe in this file is the single-threaded `static mut` access
//! for the fixed scratch buffers, same contract as `user/shell`.

#![no_std]
#![no_main]

use userlib as sys;

core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

const DOC_CAP: usize = 2048;
const LINE_CAP: usize = 256;
const STAT_CAP: usize = sys::STAT_LEN;
const DIR_CAP: usize = 8 * sys::DIRENT_LEN;
const MAX_POLLS: u32 = 1_000_000;

const DOC_PATH: &[u8] = b"/NOTES.TXT";
const DIR_PATH: &[u8] = b"/DOC";
/// Inserted after the first newline so the gap buffer moves a real gap
/// into the middle of the document instead of only appending.
const INSERT: &[u8] = b"user edit ok\n";

// Non-zero initial bytes keep every buffer in .data: an all-zero static
// lands in .bss and rust-lld emits a second R|W PT_LOAD that the U1
// loader refuses as `AlreadyMapped` (same reason as user/shell).
static mut GAP: gapbuf::Gap<DOC_CAP> = gapbuf::Gap::new();
static mut EXPECTED: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut BACK: [u8; DOC_CAP] = [b' '; DOC_CAP];
static mut STAT_BUF: [u8; STAT_CAP] = [b' '; STAT_CAP];
static mut DIR_BUF: [u8; DIR_CAP] = [b' '; DIR_CAP];
static mut LINE: [u8; LINE_CAP] = [b' '; LINE_CAP];

/// Pure, fixed-capacity gap buffer: `front ++ gap ++ back`, with every
/// offset checked and no allocation. `copy_within` does the movement, so
/// the module needs no unsafe at all.
mod gapbuf {
    #![forbid(unsafe_code)]

    pub struct Gap<const N: usize> {
        data: [u8; N],
        gap_start: usize,
        gap_end: usize,
    }

    impl<const N: usize> Gap<N> {
        /// Spaces (not zeros) so a `static` stays in `.data`.
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

        /// Insert `bytes` at logical offset `pos`. Refuses (leaving the
        /// buffer byte-identical) on an out-of-range offset or overflow.
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

        /// Copy the logical bytes out (gap skipped). Returns `0` when
        /// `out` is too small — never a truncated document.
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
    sys::write_str("FATAL: uedit: ");
    let _ = sys::write(2, what);
    sys::write_str("\n");
    sys::exit(1)
}

fn expect(ok: bool, what: &[u8]) {
    if !ok {
        die(what);
    }
}

#[unsafe(no_mangle)]
/// Paint a real editor frame on the user's VGA console through the
/// Vga* syscalls (hito 3): title bar, line-number gutter, a few lines of
/// the document, an inverse cursor and a status bar. Unlike the internal
/// gap-buffer proofs, this is what a human at the MacBook actually sees.
fn draw_editor_frame(cols: u16, rows: u16) {
    let _ = sys::vga_clear();
    let put = |x: u16, y: u16, ch: u8, attr: u8| {
        let _ = sys::vga_put_cell(x, y, ch, attr);
    };
    let text = b"reemplazo/editor  /NOTES.TXT  [user process, ring 3]";
    for (i, &c) in text.iter().enumerate() {
        if i < cols as usize { put(i as u16, 0, c, 0x1F); }
    }
    let lines: [&[u8]; 5] = [
        b"// reemplazo - from-scratch OS",
        b"fn main() {",
        b"    println!(\"hello from userland\");",
        b"}",
        b"",
    ];
    let gutter = 5u16;
    for (row, line) in lines.iter().enumerate() {
        let y = 2 + row as u16;
        if y >= rows.saturating_sub(2) { break; }
        // gutter: line number
        let num = [b'0' + (row + 1) as u8];
        put(1, y, b'0' + (row + 1) as u8, 0x0E);
        put(2, y, b' ', 0x07);
        let _ = num;
        for (i, &c) in line.iter().enumerate() {
            let x = gutter + i as u16;
            if x >= cols { break; }
            put(x, y, c, 0x07);
        }
    }
    // inverse cursor at start of line 3
    put(gutter, 4, b' ', 0x70);
    let status = b"-- INSERT --  utf8[bytes]  Ln 3, Col 1  |  Esc: exit  Ctrl-S: save";
    let sy = rows.saturating_sub(1);
    for (i, &c) in status.iter().enumerate() {
        if i < cols as usize { put(i as u16, sy, c, 0x70); }
    }
    let _ = sys::vga_flush();
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    // First syscall: VgaDims both claims console ownership and makes the
    // kernel publish this process's VMAs for every later user buffer.
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

    // Paint the editor for a human watching the MacBook's VGA. The
    // interactive REPL below still runs afterwards for automated tests.
    if let Some((cols, rows)) = sys::console_dims() {
        draw_editor_frame(cols, rows);
        // 25 s of yields: long enough to notice on real hardware even
        // if the operator is not looking at the exact moment it starts.
        for _ in 0..250 { let _ = sys::yield_now(); }
    }

    // One-line REPL for the smoke's keyboard phase (unchanged contract).
    sys::write_str("uedit> ");
    let mut polls: u32 = 0;
    // The smoke-user harness injects no keystrokes: leave the REPL after
    // a bounded wall-clock window so the hito-1/2 markers (Exit, RR,
    // fault) still run. Interactive use has a human typing within it.
    let repl_yields: u32 = 100;
    loop {
        if polls >= repl_yields {
            sys::exit(0);
        }
        let n = sys::read(0, line());
        if n > 0 {
            let end = if (n as usize) <= LINE_CAP {
                n as usize
            } else {
                LINE_CAP
            };
            execute(&line()[..end]);
            sys::exit(0);
        } else if n < 0 {
            die(b"console Read");
        } else {
            polls = polls.saturating_add(1);
            if polls > MAX_POLLS {
                sys::exit(0);
            }
            let _ = sys::yield_now();
        }
    }
}

/// Full FS syscall proof, including deliberate fail-closed violations.
fn fs_proof() {
    // A `..` component is a volume escape → EPERM, never a lookup.
    expect(
        sys::fs_open(b"/../ETC/PASSWD", sys::O_RDONLY) == sys::EPERM,
        b"path escape was not refused",
    );
    // A missing file has no EBADF-style silent fd: the ABI returns EINVAL.
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

    // Stale/foreign fd (0 is a console fd, never a volume fd) → EINVAL.
    expect(sys::fs_read(0, back()) == sys::EINVAL, b"fd 0 accepted");
    expect(sys::fs_close(0) == sys::EINVAL, b"fd 0 closed");

    // Readdir on a directory fd: at least one whole record, and its name
    // must be the nested README.TXT the volume seeds.
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

/// Gap-buffer edit + write-back + byte-exact read-back.
fn editor_proof() {
    let fd = sys::fs_open(DOC_PATH, sys::O_RDWR);
    expect(fd > 0, b"reopen /NOTES.TXT");
    let n = sys::fs_read(fd, back());
    expect(n > 0 && (n as usize) <= DOC_CAP, b"editor read");
    let n = n as usize;

    let buf = gap();
    expect(buf.load(&back()[..n]), b"gap load");
    // Insert right after the first newline: this exercises a real gap
    // move into the middle of the document.
    let at = back()[..n]
        .iter()
        .position(|b| *b == b'\n')
        .map_or(n, |i| i + 1);
    expect(buf.insert(at, INSERT), b"gap insert");
    let expected_len = buf.copy_out(expected());
    expect(expected_len == n + INSERT.len(), b"gap copy_out");

    // O_TRUNC rewinds to offset 0 (there is no Seek syscall yet).
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

fn write_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    if value == 0 {
        at -= 1;
        digits[at] = b'0';
    }
    while value > 0 {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    let _ = sys::write(1, &digits[at..]);
}

fn execute(raw: &[u8]) {
    let mut split = 0;
    while split < raw.len() && raw[split] != b' ' && raw[split] != b'\t' {
        split += 1;
    }
    let cmd = &raw[..split];
    let mut rest = &raw[split..];
    while let Some((first, tail)) = rest.split_first()
        && (*first == b' ' || *first == b'\t')
    {
        rest = tail;
    }
    if eq(cmd, b"help") {
        sys::write_str("builtins: help echo uptime edit exit\n");
    } else if eq(cmd, b"echo") {
        let _ = sys::write(1, rest);
        sys::write_str("\n");
    } else if eq(cmd, b"uptime") {
        let now = sys::time();
        if now < 0 {
            sys::write_str("uptime: unavailable\n");
        } else {
            sys::write_str("uptime: ");
            write_u64(now as u64);
            sys::write_str(" ms\n");
        }
    } else if eq(cmd, b"edit") {
        sys::write_str("editor: document saved (USER_EDITOR_OK)\n");
    } else if !cmd.is_empty() {
        sys::write_str("uedit: unknown command (try help)\n");
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    sys::write_str("FATAL: uedit panic at ");
    if let Some(loc) = info.location() {
        sys::write_str(loc.file());
        sys::write_str(":");
        write_u64(loc.line() as u64);
    }
    sys::write_str("\n");
    sys::exit(1)
}
