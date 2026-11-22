//! `netlog` — the serial console served over TCP (bring-up mode).
//!
//! The kernel prints everything with `serial_println!`, but the real
//! target (the 2007 MacBook) has no usable serial port. [`push`]
//! keeps every print in a static 32 KiB ring — hooked from
//! `SerialPort::write_str`, so the panic path is captured too — and
//! [`pump`] serves that ring to one TCP client on [`PORT`]:
//! the history first (a cursor walks the ring from the beginning of
//! the session), then the live tail. When the reader fell behind the
//! ring, the lost byte count is reported **to the client** as a
//! `netlog: overrun: …` line — never printed to serial, because a
//! print inside this module would recurse into [`push`].
//!
//! Neutrality: [`push`] runs on every serial print in every boot (a
//! bounded copy — no allocation, no output of its own), while
//! [`pump`] returns after one bool test unless
//! [`crate::netstack::Stack::netlog_listen`] was called — and only
//! the hardware bring-up mode (`crate::hwtest`) ever calls that.
//! Normal boots open no port and print nothing new: the 30-marker
//! `smoke` chain stays byte-identical.

use crate::netstack::Stack;
use core::ptr::addr_of_mut;
use smoltcp::socket::tcp;

/// Ring capacity: 32 KiB of serial history. Bounded on purpose —
/// the target has 2.9 GB of RAM but the ring is a *debug* channel,
/// and a reader that connects late must still get a report of what
/// it missed rather than an unbounded buffer.
pub const CAP: usize = 32 * 1024;

/// TCP port of the netlog service. The QEMU harness forwards it
/// (`hostfwd=tcp:0.0.0.0:2224-:2224`); on the real MacBook it is
/// reachable on the LAN address directly.
pub const PORT: u16 = 2224;

/// The ring index is `written & (CAP - 1)` — CAP must be a power of two.
const _: () = assert!(CAP.is_power_of_two());

/// The ring: the last [`CAP`] bytes pushed, plus the absolute count
/// of bytes ever pushed. `written` only grows, so a reader's cursor
/// is an absolute offset into that infinite stream and "the oldest
/// byte still alive" is `written - CAP`.
struct Ring {
    buf: [u8; CAP],
    written: u64,
}

/// Single-use ring (the `STORAGE`/`RX` idiom of `netstack.rs`/
/// `sshd.rs`): written and read only under the interrupt mask of
/// [`push`]/[`read_from`], single core.
static mut RING: Ring = Ring {
    buf: [0; CAP],
    written: 0,
};

/// Append serial bytes to the ring. Called from
/// `SerialPort::write_str` for every print (panic path included).
///
/// Never prints, never allocates, never fails: the overrun accounting
/// is done by the *reader* ([`pump`]), so a full ring here just
/// overwrites the oldest bytes — cost is one bounded copy, whatever
/// a reader (or nobody) does with it.
pub fn push(bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    let flags = crate::heap::save_and_disable();
    // SAFETY: single core, interrupts masked for the whole mutation
    // (the heap.rs `IrqCell` contract: `save_and_disable` snapshots
    // RFLAGS and `cli`s, `restore` puts the caller's exact IF bit
    // back — so a print with interrupts already off, e.g. early boot
    // or the panic path, never re-enables them). `RING` is reachable
    // only from `push` and `read_from`, both under this same mask, so
    // an interrupt-time print (a panic raised from an exception)
    // cannot interleave with a mainline copy and corrupt the cursor.
    // No printing anywhere below: that would recurse straight back
    // into `serial_print!` → `push`.
    unsafe {
        let ring = &mut *addr_of_mut!(RING);
        // A single push larger than the ring keeps only its tail —
        // exactly what the sliding window means — while `written`
        // still advances by the full length, so cursors and the
        // overrun math stay honest.
        let n = bytes.len().min(CAP);
        let src = &bytes[bytes.len() - n..];
        let start = (ring.written.wrapping_add((bytes.len() - n) as u64) as usize) & (CAP - 1);
        let head = (CAP - start).min(n);
        ring.buf[start..start + head].copy_from_slice(&src[..head]);
        if n > head {
            ring.buf[..n - head].copy_from_slice(&src[head..]);
        }
        ring.written = ring.written.wrapping_add(bytes.len() as u64);
    }
    crate::heap::restore(flags);
}

/// Read from the ring at the absolute cursor `cursor`.
///
/// Returns `(lost, copied)`: `lost` is how many bytes had already
/// fallen out of the ring *before* `cursor` (the caller must add it
/// to its cursor — those bytes are gone — and report it to its
/// client), and `copied` is how many bytes were written into `out`,
/// starting at the oldest byte still alive (`cursor + lost`).
fn read_from(cursor: u64, out: &mut [u8]) -> (u64, usize) {
    let flags = crate::heap::save_and_disable();
    // SAFETY: same mask/single-core contract as `push`: the copy and
    // the `written` snapshot are atomic with respect to any
    // interrupt-time print, so the window cannot be overwritten under
    // us mid-copy. Read-only otherwise; no printing (no recursion).
    let (lost, copied) = unsafe {
        let ring = &mut *addr_of_mut!(RING);
        let written = ring.written;
        let oldest = written.saturating_sub(CAP as u64);
        let (cursor, lost) = if cursor < oldest {
            (oldest, oldest - cursor)
        } else {
            (cursor, 0)
        };
        let avail = written.saturating_sub(cursor);
        let n = avail.min(out.len() as u64) as usize;
        let start = (cursor as usize) & (CAP - 1);
        let head = (CAP - start).min(n);
        out[..head].copy_from_slice(&ring.buf[start..start + head]);
        if n > head {
            out[head..n].copy_from_slice(&ring.buf[..n - head]);
        }
        (lost, n)
    };
    crate::heap::restore(flags);
    (lost, copied)
}

/// Format the overrun notice for the client —
/// `netlog: overrun: <lost> bytes lost (ring full)\n`, printable
/// ASCII only. Returns the length written into `out` (the line is
/// 61 bytes worst case, `out` is 96).
fn overrun_line(out: &mut [u8], lost: u64) -> usize {
    const PREFIX: &[u8] = b"netlog: overrun: ";
    const SUFFIX: &[u8] = b" bytes lost (ring full)\n";
    debug_assert!(out.len() >= PREFIX.len() + 20 + SUFFIX.len());
    let mut len = 0;
    out[..PREFIX.len()].copy_from_slice(PREFIX);
    len += PREFIX.len();
    // u64 → decimal, no formatting machinery (no_std, no alloc).
    let mut digits = [0u8; 20];
    let mut count = 0usize;
    let mut n = lost;
    loop {
        digits[count] = b'0' + (n % 10) as u8;
        count += 1;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for i in (0..count).rev() {
        out[len] = digits[i];
        len += 1;
    }
    for &b in SUFFIX {
        out[len] = b;
        len += 1;
    }
    len
}

/// Stream the ring to the netlog client — called from
/// [`Stack::poll`] on every stack iteration.
///
/// Returns immediately (one bool test) unless
/// [`Stack::netlog_listen`] armed the socket, so normal boots pay
/// ~0 for this. One client at a time: history first (the cursor
/// starts at 0 per session), then the live tail; when the client
/// leaves, the session resets and the socket listens again.
pub fn pump(stack: &mut Stack) {
    if !stack.netlog_enabled {
        return; // normal boots: no listener, no work (neutrality)
    }
    let handle = stack.netlog_handle;
    let state = stack.sockets.get::<tcp::Socket>(handle).state();
    if state == tcp::State::Listen {
        return; // no client yet
    }
    if state != tcp::State::Established {
        // The client is gone (FIN/RST), or a handshake died. Reset
        // the session — the next client replays the history — and
        // listen again, the `listen_ssh` pattern: abort whatever is
        // open first (`listen` refuses an open socket), TimeWait and
        // Closed listen directly.
        if stack.netlog_streaming {
            stack.netlog_streaming = false;
            stack.netlog_cursor = 0;
            stack.netlog_report = 0;
            let sock = stack.sockets.get_mut::<tcp::Socket>(handle);
            if sock.is_open() {
                sock.abort();
            }
            let _ = sock.listen(PORT);
        }
        return;
    }
    if !stack.netlog_streaming {
        // Fresh connection: replay the whole retained history first,
        // then follow the tail (the cursor walks forward from here).
        stack.netlog_streaming = true;
        stack.netlog_cursor = 0;
        stack.netlog_report = 0;
    }

    // Read first, so a fresh overrun is reported *before* the data
    // that follows the gap. The cursor only commits the `lost` jump
    // here — the `copied` bytes commit below, by what the socket
    // actually accepted (an unsent chunk is re-read next poll).
    let mut chunk = [0u8; 2048];
    let (lost, copied) = read_from(stack.netlog_cursor, &mut chunk);
    if lost > 0 {
        stack.netlog_cursor = stack.netlog_cursor.wrapping_add(lost);
        stack.netlog_report = stack.netlog_report.saturating_add(lost);
    }

    // Overrun report: to the client only — printing it would recurse
    // into `push`. Deferred while the tx buffer cannot take the whole
    // line (a half line would garble it); order before data matters.
    if stack.netlog_report > 0 {
        let mut line = [0u8; 96];
        let len = overrun_line(&mut line, stack.netlog_report);
        let free = {
            let sock = stack.sockets.get::<tcp::Socket>(handle);
            sock.send_capacity().saturating_sub(sock.send_queue())
        };
        if free < len {
            return; // tx full: report and data both wait one poll
        }
        match stack
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(&line[..len])
        {
            // `free >= len` ⇒ the whole line fit (enqueue_slice takes
            // min(free, len)); an Ok(_) with less would mean a state
            // change mid-call, which cannot happen on one core —
            // drop the report rather than resend a half line.
            Ok(_) => stack.netlog_report = 0,
            Err(_) => return, // not sendable: retry next poll
        }
    }

    if copied == 0 {
        return; // nothing new since the last poll
    }
    let sent = stack
        .sockets
        .get_mut::<tcp::Socket>(handle)
        .send_slice(&chunk[..copied])
        .unwrap_or(0); // state changed under us → try again next poll
    stack.netlog_cursor = stack.netlog_cursor.wrapping_add(sent as u64);
}
