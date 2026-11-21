//! Client-side TCP (RFC 9293) over the e1000 driver: active open, one
//! request/response exchange, and an orderly close — proven by an
//! HTTP/1.1 GET against `github.com:80`, whose `Connection: close`
//! reply exercises FIN in both directions (the smoke test's `TCP_OK`).
//!
//! Wire format, checksum validation, and RFC 1982 serial-number
//! arithmetic live in the host-tested `net::tcp` crate; this file
//! drives the NIC and owns the connection state.
//!
//! Scope of this milestone (documented limits, not hidden bugs):
//! retransmission is poll-based with a fixed attempt count (SYN,
//! request, FIN) — no RTO backoff or timers until the PIT milestone;
//! there is no out-of-order reassembly (a gap gets a duplicate ACK and
//! the sender's retransmission fills it — correct, just not optimal);
//! no congestion control or delayed ACK (one small segment at a time,
//! every data segment is ACKed immediately); the receive side is a
//! fixed buffer that only shrinks — one response per connection, no
//! streaming (that arrives with the HTTP milestone); and urgent (URG)
//! data is consumed in-band like everything else, since nothing we
//! speak uses out-of-band semantics.

use crate::dhcp::NetConfig;
use crate::e1000::{E1000, RX_POLLS};
use crate::entropy::boot_entropy;
use net::Endpoint;
use net::on_subnet;
use net::tcp::{self, FLAG_ACK, FLAG_FIN, FLAG_PSH, FLAG_RST, FLAG_SYN, TcpHeader};

/// Retransmission attempts per phase (SYN, request, FIN) before giving
/// up loudly.
const ATTEMPTS: u32 = 3;
/// Spin budget per wait: a slice of the driver-wide `RX_POLLS` picked
/// so that [`ATTEMPTS`] retransmissions still finish inside the smoke
/// test's window (a dead path must print its FATAL before the harness
/// kills QEMU) while one wait alone still covers a real round trip
/// through slirp → container → internet.
const POLLS: u32 = RX_POLLS / 8;
/// Largest single-segment send, one MSS: segmentation of bulk data
/// belongs to the git milestone.
const MAX_SEND: usize = 1460;
/// Largest frame we transmit: eth + IPv4 + TCP + MSS option + MSS.
const MAX_FRAME: usize = 14 + 20 + 20 + 4 + MAX_SEND;
/// Receive buffer for the whole response. The smoke test reads the
/// headers of a `Content-Length: 0` redirect; anything larger aborts
/// loudly — streaming belongs to the HTTP milestone.
const RESP_CAP: usize = 4096;

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: tcp: {msg}");
    crate::halt()
}

/// Prove the whole client-side TCP lifecycle against a real server:
/// resolve the next hop, open a connection to `remote_ip:80`, send one
/// HTTP/1.1 GET with `Connection: close`, read the response until the
/// server's FIN, validate it, close our side, print `TCP_OK`.
pub fn http_smoke(nic: &mut E1000, cfg: &NetConfig, remote_ip: [u8; 4], host: &str) {
    let mut conn = Conn::open(nic, cfg, remote_ip, 80);

    // HTTP/1.1 requires a Host header; `Connection: close` makes the
    // server FIN after the response, which gives us a full
    // bidirectional close to prove.
    let mut req = [0u8; 256];
    let req_len = build_get(&mut req, host);
    conn.send(nic, &req[..req_len]);

    // Read until the server's FIN; retransmit the request while it is
    // unacknowledged and while nothing arrives at all.
    let mut resp = [0u8; RESP_CAP];
    let mut cursor = 0;
    let mut stalls = 0;
    while !conn.fin_seen {
        match conn.recv(nic, &mut resp[cursor..]) {
            Some(n) => {
                cursor += n;
                stalls = 0;
            }
            None => {
                stalls += 1;
                if stalls > ATTEMPTS {
                    fatal("timeout waiting for the HTTP response");
                }
                conn.resend(nic, &req[..req_len]);
            }
        }
    }

    // A real HTTP status line and a complete header block, or we did
    // not get what we asked for.
    let resp = &resp[..cursor];
    if !resp.starts_with(b"HTTP/1.") || !headers_complete(resp) {
        fatal("response is not a complete HTTP/1.x header block");
    }

    // Print the status line. The bytes are external input: only a
    // printable-ASCII line reaches the serial log, so a crafted
    // newline cannot split the log (log injection into the smoke
    // harness's line stream).
    let line_end = resp
        .iter()
        .position(|&b| b == b'\r' || b == b'\n')
        .unwrap_or(resp.len());
    if resp[..line_end].iter().all(|b| (0x20..=0x7E).contains(b)) {
        if let Ok(line) = core::str::from_utf8(&resp[..line_end]) {
            serial_println!("tcp: {line}");
        }
    } else {
        serial_println!("tcp: (status line contains non-printable bytes)");
    }

    conn.close(nic);
    serial_println!("TCP_OK"); // machine-checked by `cargo xtask smoke`
}

/// Assemble `GET / HTTP/1.1` with the `Host` header and
/// `Connection: close` into `buf`, returning its length.
fn build_get(buf: &mut [u8], host: &str) -> usize {
    const PREFIX: &[u8] = b"GET / HTTP/1.1\r\nHost: ";
    const SUFFIX: &[u8] = b"\r\nConnection: close\r\n\r\n";
    let total = PREFIX.len() + host.len() + SUFFIX.len();
    let b = match buf.get_mut(..total) {
        Some(b) => b,
        None => fatal("GET request does not fit the buffer"),
    };
    b[..PREFIX.len()].copy_from_slice(PREFIX);
    b[PREFIX.len()..PREFIX.len() + host.len()].copy_from_slice(host.as_bytes());
    b[PREFIX.len() + host.len()..].copy_from_slice(SUFFIX);
    total
}

/// True once the header-terminating empty line (`\r\n\r\n`) is present.
fn headers_complete(resp: &[u8]) -> bool {
    resp.windows(4).any(|w| w == b"\r\n\r\n")
}

/// One client connection. Sequence fields follow RFC 9293 §3.2:
/// `snd_una` (oldest unacked) … `snd_nxt` (next to send), and
/// `rcv_nxt` (next expected from the peer) — all compared with the
/// wrapping helpers in `net::tcp`, because they wrap past 2^32.
struct Conn {
    src: Endpoint, // our MAC + leased IP
    dst: Endpoint, // next-hop MAC + remote IP (MAC is the *router*
    //                  when the server is off-subnet)
    local_port: u16,
    remote_port: u16,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    /// The peer's last advertised receive window (for send bounds).
    peer_window: u16,
    /// Response bytes stored so far: our advertised window is
    /// `RESP_CAP - rx_used` and never grows back (one response).
    rx_used: usize,
    /// The peer's FIN has been received and acknowledged.
    fin_seen: bool,
}

impl Conn {
    /// Active open: resolve the next hop (the server itself when it is
    /// on-subnet, the router otherwise), then SYN → SYN+ACK → ACK.
    ///
    /// The SYN carries our MSS option and is retransmitted up to
    /// [`ATTEMPTS`] times; a brand-new connection's first segment must
    /// be *exactly* SYN — no ACK bit (slirp drops anything else,
    /// verified in its `tcp_input.c`). The ISN and local port come
    /// from [`boot_entropy`](crate::entropy::boot_entropy): weak but
    /// non-constant, which defeats off-path injection (RFC 6528 §3).
    fn open(nic: &mut E1000, cfg: &NetConfig, remote_ip: [u8; 4], remote_port: u16) -> Conn {
        let hop_ip = if on_subnet(cfg.ip, cfg.netmask, remote_ip) {
            remote_ip
        } else {
            cfg.router
        };
        let hop_mac = nic.arp_resolve(cfg.ip, hop_ip);

        let ent = boot_entropy();
        // IANA dynamic range 49152..=65535 (RFC 6335 §6): the mask
        // keeps the addend in 14 bits, so the u16 sum cannot overflow.
        let local_port = 49152u16 + ((ent & 0x3FFF) as u16);
        let isn = ent;
        let mut conn = Conn {
            src: Endpoint::new(nic.mac(), cfg.ip),
            dst: Endpoint::new(hop_mac, remote_ip),
            local_port,
            remote_port,
            snd_una: isn,                 // the SYN is outstanding from ISN
            snd_nxt: isn.wrapping_add(1), // the SYN occupies one seq number
            rcv_nxt: 0,
            peer_window: 0,
            rx_used: 0,
            fin_seen: false,
        };

        let mut rx = [0u8; 2048];
        for attempt in 1..=ATTEMPTS {
            // Retransmissions reuse snd_una (= ISN until the SYN is
            // acked), so every attempt carries the same sequence number.
            conn.send_at(nic, conn.snd_una, FLAG_SYN, &tcp::MSS_OPTION, &[]);
            serial_println!(
                "tcp: SYN -> {}.{}.{}.{}:{remote_port} (attempt {attempt})",
                remote_ip[0],
                remote_ip[1],
                remote_ip[2],
                remote_ip[3]
            );
            let mut spins = 0;
            loop {
                if spins >= POLLS {
                    break; // this attempt timed out → retransmit
                }
                spins += 1;
                let Some(seg) = conn.step(nic, &mut rx) else {
                    core::hint::spin_loop();
                    continue;
                };
                // The handshake reply: SYN+ACK (ECN bits may ride
                // along, FIN may not), acknowledging exactly our ISN+1.
                if seg.flags & (FLAG_SYN | FLAG_ACK | FLAG_FIN) != (FLAG_SYN | FLAG_ACK) {
                    continue;
                }
                if seg.ack != conn.snd_nxt {
                    continue;
                }
                // Their ISN is consumed by their SYN.
                conn.rcv_nxt = seg.seq.wrapping_add(1);
                conn.send_at(nic, conn.snd_nxt, FLAG_ACK, &[], &[]);
                return conn;
            }
        }
        fatal("TCP handshake timed out (SYN retransmits exhausted)");
    }

    /// Send one segment of application data (PSH+ACK). One outstanding
    /// segment at a time: sending again before the first is acked is a
    /// caller bug (caught loudly), and [`Conn::resend`] retransmits the
    /// unacked bytes from `snd_una`. Data larger than one MSS is
    /// rejected — bulk segmentation belongs to the git milestone.
    fn send(&mut self, nic: &mut E1000, data: &[u8]) {
        if data.is_empty() || data.len() > MAX_SEND {
            fatal("send must be 1..=MSS bytes (no segmentation yet)");
        }
        if self.snd_una != self.snd_nxt {
            fatal("previous send still unacknowledged (single outstanding segment)");
        }
        if data.len() > usize::from(self.usable_window()) {
            fatal("peer window too small for the request (zero-window persist not implemented)");
        }
        self.send_at(nic, self.snd_nxt, FLAG_PSH | FLAG_ACK, &[], data);
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
    }

    /// Wait for the next event this connection delivers: in-order
    /// payload (returns its length) or the peer's FIN (returns 0 and
    /// sets `fin_seen`). `None` when [`POLLS`] spins pass without one —
    /// the caller decides whether to retransmit or give up. Pure ACKs,
    /// duplicates, and gaps are consumed internally (re-ACKed where
    /// useful) and never returned; the spin counter bounds them all.
    fn recv(&mut self, nic: &mut E1000, out: &mut [u8]) -> Option<usize> {
        let mut rx = [0u8; 2048];
        let mut spins = 0;
        loop {
            if spins >= POLLS {
                return None;
            }
            spins += 1;
            let Some(seg) = self.step(nic, &mut rx) else {
                core::hint::spin_loop();
                continue;
            };
            if let Some(n) = self.consume(nic, &seg, Some(&mut out[..])) {
                return Some(n);
            }
            // Pure ACK or a re-ACKed duplicate: nothing delivered —
            // keep waiting within the same spin budget.
        }
    }

    /// Retransmit the unacked tail of `data` — which must be exactly
    /// what the last [`Conn::send`] transmitted (single outstanding
    /// segment by design) — starting at `snd_una`, its first
    /// unacknowledged byte. A fully acknowledged send is a no-op.
    fn resend(&mut self, nic: &mut E1000, data: &[u8]) {
        if !self.has_unacked() {
            return;
        }
        let base = self.snd_nxt.wrapping_sub(data.len() as u32);
        let offset = self.snd_una.wrapping_sub(base) as usize;
        if offset >= data.len() {
            fatal("resend offset outside the outstanding segment (state bug)");
        }
        self.send_at(nic, self.snd_una, FLAG_PSH | FLAG_ACK, &[], &data[offset..]);
    }

    /// Orderly teardown: send FIN (retransmitted on stall), consume
    /// whatever the peer still sends — their FIN when it arrives,
    /// duplicate FINs re-ACKed, stray payload discarded (the module
    /// docs scope that) — and finish when they acknowledge our FIN.
    fn close(&mut self, nic: &mut E1000) {
        let fin_seq = self.snd_nxt;
        self.send_at(nic, fin_seq, FLAG_FIN | FLAG_ACK, &[], &[]);
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        serial_println!("tcp: FIN sent, waiting for the peer to close");

        let mut rx = [0u8; 2048];
        let mut attempts = 1; // the FIN we just sent
        let mut spins = 0;
        loop {
            // Done when their FIN is consumed and everything we sent —
            // including the FIN — has been acknowledged.
            if self.fin_seen && self.snd_una == self.snd_nxt {
                serial_println!("tcp: connection closed cleanly");
                return;
            }
            if spins >= POLLS {
                attempts += 1;
                if attempts > ATTEMPTS {
                    fatal("timeout closing connection (peer never acknowledged our FIN)");
                }
                // Retransmit the FIN from its original sequence number.
                self.send_at(nic, fin_seq, FLAG_FIN | FLAG_ACK, &[], &[]);
                spins = 0;
                continue;
            }
            spins += 1;
            let Some(seg) = self.step(nic, &mut rx) else {
                core::hint::spin_loop();
                continue;
            };
            let _ = self.consume(nic, &seg, None); // discard payload; re-ACK dups/FIN
            // then re-check the done condition
        }
    }

    /// True while bytes we sent are not yet acknowledged.
    fn has_unacked(&self) -> bool {
        self.snd_una != self.snd_nxt
    }

    /// What we may still send: the peer's window minus what is in
    /// flight under it. (Window *scaling* is not negotiated — our SYN
    /// offers only MSS — so the raw field is literal.)
    fn usable_window(&self) -> u16 {
        let outstanding = self.snd_nxt.wrapping_sub(self.snd_una);
        let outstanding = u16::try_from(outstanding).unwrap_or(u16::MAX);
        self.peer_window.saturating_sub(outstanding)
    }

    /// Our advertised receive window: the fixed buffer space left.
    /// It shrinks as the response fills it and never grows back (one
    /// response per connection), so the peer can never push more bytes
    /// than we can hold.
    fn window(&self) -> u16 {
        u16::try_from(RESP_CAP - self.rx_used).unwrap_or(0)
    }

    /// Build and transmit one segment on this connection: our ports,
    /// `seq`, the current `rcv_nxt` as ack, and the current receive
    /// window. `net::tcp::build_frame` computes both checksums after
    /// every byte is in place (the DHCP-checksum lesson).
    fn send_at(&self, nic: &mut E1000, seq: u32, flags: u8, options: &[u8], payload: &[u8]) {
        let hdr = TcpHeader {
            src_port: self.local_port,
            dst_port: self.remote_port,
            seq,
            ack: self.rcv_nxt,
            flags,
            window: self.window(),
        };
        let mut frame = [0u8; MAX_FRAME];
        let n = match tcp::build_frame(&mut frame, self.src, self.dst, hdr, options, payload) {
            Some(n) => n,
            None => fatal("cannot build TCP segment (buffer or length bug)"),
        };
        if let Err(e) = nic.transmit(&frame[..n]) {
            fatal(e);
        }
    }

    /// Send a bare ACK for everything received so far.
    fn send_ack(&self, nic: &mut E1000) {
        self.send_at(nic, self.snd_nxt, FLAG_ACK, &[], &[]);
    }

    /// Decide whether `seg` belongs to this connection and bookkeep it:
    /// the 4-tuple must match exactly (the NIC is promiscuous — every
    /// frame on the segment reaches us), a RST on our connection is
    /// fatal, and an ack beyond `snd_nxt` claims bytes we never sent —
    /// no legitimate stack can produce that, so the segment is dropped,
    /// never trusted. A fresh in-range ack advances `snd_una`, and the
    /// peer's window is remembered for send bounds.
    fn accept(&mut self, seg: &tcp::TcpSegment) -> bool {
        if seg.src_ip != self.dst.ip
            || seg.dst_ip != self.src.ip
            || seg.src_port != self.remote_port
            || seg.dst_port != self.local_port
        {
            return false;
        }
        if seg.flags & FLAG_RST != 0 {
            fatal("connection reset by peer (RST)");
        }
        if tcp::seq_gt(seg.ack, self.snd_nxt) {
            return false; // acks data we never sent — dropped, not trusted
        }
        if tcp::seq_gt(seg.ack, self.snd_una) {
            self.snd_una = seg.ack;
        }
        self.peer_window = seg.window;
        true
    }

    /// One non-blocking pull from the RX ring: `Some(seg)` when a
    /// segment for this connection arrived (validated and bookkept by
    /// `accept`), `None` when the ring was empty or the frame was not
    /// ours — the caller owns the spin budget, which is what bounds
    /// adversarial segment floods too.
    fn step<'a>(&mut self, nic: &mut E1000, rx: &'a mut [u8]) -> Option<tcp::TcpSegment<'a>> {
        let n = nic.receive(rx)?;
        let seg = tcp::parse_frame(&rx[..n])?;
        self.accept(&seg).then_some(seg)
    }

    /// Process one accepted segment: append in-order payload to `out`
    /// (discard it when `out` is `None` — the close path has stopped
    /// reading, see module docs), consume an in-order FIN, and ACK
    /// everything consumed. Returns `Some(bytes)` when a payload or a
    /// FIN was consumed, `None` for a pure ACK or a duplicate/gap —
    /// those are re-ACKed but deliver nothing. RST never reaches here
    /// (`accept` fatals on it).
    fn consume(
        &mut self,
        nic: &mut E1000,
        seg: &tcp::TcpSegment,
        out: Option<&mut [u8]>,
    ) -> Option<usize> {
        let plen = seg.payload.len();
        if plen > 0 {
            if seg.seq != self.rcv_nxt {
                // Duplicate or gap: there is no reassembly queue (see
                // module docs) — re-ACK our state so a compliant sender
                // retransmits the missing bytes from rcv_nxt (or stops
                // resending duplicates).
                self.send_ack(nic);
                return None;
            }
            if let Some(buf) = out {
                if plen > buf.len() {
                    fatal(
                        "HTTP response exceeds the fixed buffer (streaming comes with the HTTP milestone)",
                    );
                }
                buf[..plen].copy_from_slice(seg.payload);
                self.rx_used += plen;
            }
            // `out == None` (close path): sequence numbers still advance.
            self.rcv_nxt = self.rcv_nxt.wrapping_add(plen as u32);
            let fin = seg.flags & FLAG_FIN != 0;
            if fin {
                // The FIN occupies the sequence number right after the
                // payload, which rcv_nxt now points at.
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.fin_seen = true;
            }
            self.send_ack(nic);
            return Some(plen);
        }
        if seg.flags & FLAG_FIN != 0 {
            if seg.seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.fin_seen = true;
                self.send_ack(nic);
                return Some(0);
            }
            self.send_ack(nic); // duplicate or out-of-order FIN
            return None;
        }
        None // pure ACK: snd_una was already advanced by `accept`
    }
}
