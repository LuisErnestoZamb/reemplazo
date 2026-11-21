//! smoltcp integration: the e1000 driver behind `phy::Device`, the
//! static storage the stack lives in, and the `Stack` the boot chain
//! and the shell drive. The evaluation, verified facts and migration
//! plan live in `docs/smoltcp-eval.md`.
//!
//! Boot phases mirror the smoke's marker order exactly (all16
//! markers keep their meaning — only producers moved):
//!
//! ```text
//! set_static_ipv4 → prove_ping   → NET_OK (ARP-reply sniff) + PING_OK
//!                → wait_lease    → DHCP_OK (slirp values asserted)
//!                → resolve       → DNS_OK  → plain_get_smoke → TCP_OK
//! tls::https_smoke               → TLS_OK + HTTP_OK
//! ```
//!
//! The DHCP socket is added **only after PING_OK** (risk R7): a fresh
//! DHCP socket's first `poll()` reports `Deconfigured`, which would
//! wipe the static address the first two phases rely on.

use crate::clock;
use crate::e1000::E1000;
use core::ptr::addr_of_mut;
use net::http;
use net::{SLIRP_GATEWAY, SLIRP_GUEST_IP};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::dhcpv4::{self, Event as DhcpEvent};
use smoltcp::socket::dns::{self, GetQueryResultError};
use smoltcp::socket::{icmp, tcp};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{
    DnsQueryType, EthernetAddress, HardwareAddress, Icmpv4Packet, Icmpv4Repr, IpAddress, IpCidr,
    Ipv4Address, Ipv4Cidr,
};

/// Deadline for every boot/shell network operation: DHCP10 s, DNS10 s,
/// TCP10 s (smoltcp retransmits inside the window — spin counts are
/// gone, see docs/smoltcp-eval.md §6).
pub const OP_DEADLINE_MS: u64 = 10_000;
/// Echo identity used everywhere (boot proof and shell `ping`): the
/// ICMP socket is bound to it once, so replies with other ids are
/// filtered by smoltcp itself.
const ECHO_ID: u16 = 0x5252;

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: net: {msg}");
    crate::halt()
}

/// Ethernet frame size we hand to/from the stack (14 B header +
/// 1500 B MTU) — also the bound of one e1000 ring slot.
pub const FRAME: usize = 1514;

/// Our e1000 driver behind smoltcp's [`Device`]: copies frames in and
/// out of the synchronous 16-descriptor ring exactly like the old
/// hand-rolled path did, and sniffs the gateway's ARP reply so the
/// boot chain can still print `NET_OK` with its historical meaning —
/// smoltcp's neighbor cache is private, but the driver sees every
/// frame (docs/smoltcp-eval.md §9).
pub struct E1000Phy {
    dev: E1000,
    /// The stack resolved the gateway and a reply came back on RX.
    pub saw_arp_reply: bool,
}

impl E1000Phy {
    pub fn new(dev: E1000) -> Self {
        E1000Phy {
            dev,
            saw_arp_reply: false,
        }
    }

    pub fn mac(&self) -> [u8; 6] {
        self.dev.mac()
    }

    /// Same filter the old `arp_resolve` used: an ARP *reply* whose
    /// sender protocol address is the gateway and whose destination
    /// MAC is ours (raw offsets — this must not depend on the frame
    /// helpers the migration deletes).
    fn sniff_arp_reply(&mut self, frame: &[u8]) {
        if frame.len() < 42 {
            return;
        }
        if frame[12..14] != [0x08, 0x06] {
            return; // not Ethernet/ARP
        }
        if frame[20..22] != [0x00, 0x02] {
            return; // not a reply
        }
        if frame[28..32] != SLIRP_GATEWAY {
            return; // not from the gateway we are resolving
        }
        if frame[0..6] != self.dev.mac() {
            return; // not addressed to us
        }
        self.saw_arp_reply = true;
    }
}

/// RX token: one frame copied out of the ring (the slot is reclaimed
/// inside `E1000::receive`, before the token is even handed over).
pub struct Rx {
    frame: [u8; FRAME],
    len: usize,
}

impl RxToken for Rx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame[..self.len])
    }
}

/// TX token: fills a scratch frame through the closure, then commits
/// it to the ring — the "payload written, descriptor published"
/// pairing `E1000::transmit` already implements.
pub struct Tx<'a> {
    phy: &'a mut E1000Phy,
}

impl TxToken for Tx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = [0u8; FRAME];
        let result = f(&mut buf[..len]);
        if let Err(e) = self.phy.dev.transmit(&buf[..len]) {
            // Boot-time policy: a ring that never completes is fatal,
            // exactly as every other transmit path in this driver.
            serial_println!("FATAL: e1000: {e}");
            crate::halt();
        }
        result
    }
}

impl Device for E1000Phy {
    type RxToken<'a>
        = Rx
    where
        Self: 'a;
    type TxToken<'a>
        = Tx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Rx, Tx<'_>)> {
        let mut frame = [0u8; FRAME];
        let len = self.dev.receive(&mut frame)?;
        self.sniff_arp_reply(&frame[..len]);
        Some((Rx { frame, len }, Tx { phy: self }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Tx<'_>> {
        Some(Tx { phy: self })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = FRAME; // default is 0 — must be set
        caps.max_burst_size = Some(16); // matches the e1000 ring
        caps
    }
}

/// What the DHCP lease gave us — kept for the shell's `netinfo` and
/// for the boot assertions (the old parser regression tests).
#[derive(Debug, Clone, Copy)]
pub struct LeaseInfo {
    pub address: Ipv4Cidr,
    pub router: Option<Ipv4Address>,
    /// DNS servers from the lease (at most `DHCP_MAX_DNS_SERVER_COUNT`
    /// fit; `count` says how many of the slots are real).
    pub dns: [Ipv4Address; 4],
    pub dns_count: usize,
}

/// Everything the stack lives in, `const`-constructible for a
/// `static mut` (the same idiom as the TLS record buffers; measured
/// sizes in docs/smoltcp-eval.md §1.6 — ~11 KiB, plus the second,
/// third and fourth TCP pairs the sequential smoke connections need
/// ≈ +24 KiB).
pub struct Storage {
    pub slots: [SocketStorage<'static>; 7],
    /// First connection (the plain-HTTP proof).
    pub tcp_rx: [u8; 4096],
    pub tcp_tx: [u8; 4096],
    /// Second connection (TLS): a socket in TIME-WAIT cannot be
    /// reused for ten seconds — the smoke has no budget for that.
    pub tcp2_rx: [u8; 4096],
    pub tcp2_tx: [u8; 4096],
    /// Third connection (`git ls-remote` over TLS): same TIME-WAIT
    /// reason — each sequential connection needs its own socket.
    pub tcp3_rx: [u8; 4096],
    pub tcp3_tx: [u8; 4096],
    /// Fourth connection (SSH banner + KEXINIT, milestone S1): same
    /// TIME-WAIT reason — each sequential connection needs its own.
    pub tcp4_rx: [u8; 4096],
    pub tcp4_tx: [u8; 4096],
    pub icmp_rx_pkts: [icmp::PacketMetadata; 1],
    pub icmp_rx: [u8; 256],
    pub icmp_tx_pkts: [icmp::PacketMetadata; 1],
    pub icmp_tx: [u8; 256],
    pub dns_queries: [Option<dns::DnsQuery>; 1],
    pub dns_servers: [IpAddress; 1],
}

impl Storage {
    pub const fn new() -> Self {
        Storage {
            slots: [SocketStorage::EMPTY; 7],
            tcp_rx: [0; 4096],
            tcp_tx: [0; 4096],
            tcp2_rx: [0; 4096],
            tcp2_tx: [0; 4096],
            tcp3_rx: [0; 4096],
            tcp3_tx: [0; 4096],
            tcp4_rx: [0; 4096],
            tcp4_tx: [0; 4096],
            icmp_rx_pkts: [icmp::PacketMetadata::EMPTY; 1],
            icmp_rx: [0; 256],
            icmp_tx_pkts: [icmp::PacketMetadata::EMPTY; 1],
            icmp_tx: [0; 256],
            dns_queries: [None; 1],
            dns_servers: [IpAddress::Ipv4(Ipv4Address::UNSPECIFIED); 1],
        }
    }
}

/// Single-use stack storage (see `READ_STORAGE`-style SAFETY in
/// tls.rs): written once by [`Stack::new`] on a single core; the only
/// handler in play (IRQ0) never touches it.
static mut STORAGE: Storage = Storage::new();

/// The stack: interface + driver + socket set + the handles the boot
/// phases and the shell drive, all static-backed (no allocator).
pub struct Stack {
    pub iface: Interface,
    pub dev: E1000Phy,
    pub sockets: SocketSet<'static>,
    pub tcp_handle: SocketHandle,
    pub tcp2_handle: SocketHandle,
    pub tcp3_handle: SocketHandle,
    pub tcp4_handle: SocketHandle,
    pub icmp_handle: SocketHandle,
    pub dns_handle: SocketHandle,
    /// Added only after PING_OK (R7 — see module docs).
    pub dhcp_handle: Option<SocketHandle>,
    /// The applied lease, for `netinfo`.
    pub lease: Option<LeaseInfo>,
}

impl Stack {
    /// Wrap the initialized e1000. `random_seed` is **mandatory**
    /// (risk R1 of docs/smoltcp-eval.md): smoltcp draws TCP ISNs,
    /// source ports and DHCP transaction ids from an sPCG32 seeded
    /// here — default 0 would be a per-boot-constant ISN stream, a
    /// regression against the CSPRNG defense in `entropy.rs`.
    pub fn new(dev: E1000, random_seed: u64) -> Self {
        // SAFETY: single-use static (see STORAGE); single core, the
        // IRQ0 handler never touches it.
        let storage: &'static mut Storage = unsafe { &mut *addr_of_mut!(STORAGE) };
        let Storage {
            slots,
            tcp_rx,
            tcp_tx,
            tcp2_rx,
            tcp2_tx,
            tcp3_rx,
            tcp3_tx,
            tcp4_rx,
            tcp4_tx,
            icmp_rx_pkts,
            icmp_rx,
            icmp_tx_pkts,
            icmp_tx,
            dns_queries,
            dns_servers,
        } = storage;
        dns_servers[0] = IpAddress::Ipv4(Ipv4Address::new(
            net::SLIRP_DNS[0],
            net::SLIRP_DNS[1],
            net::SLIRP_DNS[2],
            net::SLIRP_DNS[3],
        ));

        let mut dev = E1000Phy::new(dev);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(dev.mac())));
        config.random_seed = random_seed; // R1 condition
        let iface = Interface::new(config, &mut dev, clock::now());

        let mut sockets = SocketSet::new(&mut slots[..]);
        let tcp_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut tcp_rx[..]),
            tcp::SocketBuffer::new(&mut tcp_tx[..]),
        ));
        let tcp2_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut tcp2_rx[..]),
            tcp::SocketBuffer::new(&mut tcp2_tx[..]),
        ));
        let tcp3_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut tcp3_rx[..]),
            tcp::SocketBuffer::new(&mut tcp3_tx[..]),
        ));
        let tcp4_handle = sockets.add(tcp::Socket::new(
            tcp::SocketBuffer::new(&mut tcp4_rx[..]),
            tcp::SocketBuffer::new(&mut tcp4_tx[..]),
        ));
        let icmp_handle = sockets.add(icmp::Socket::new(
            icmp::PacketBuffer::new(&mut icmp_rx_pkts[..], &mut icmp_rx[..]),
            icmp::PacketBuffer::new(&mut icmp_tx_pkts[..], &mut icmp_tx[..]),
        ));
        let dns_handle = sockets.add(dns::Socket::new(&dns_servers[..], &mut dns_queries[..]));
        for handle in [tcp_handle, tcp2_handle, tcp3_handle, tcp4_handle] {
            // With `socket-tcp-reno` enabled Reno is already the
            // default; setting it documents the choice (cubic is f64
            // and deliberately off — docs/smoltcp-eval.md §1.2).
            sockets
                .get_mut::<tcp::Socket>(handle)
                .set_congestion_control(tcp::CongestionControl::Reno);
            sockets
                .get_mut::<tcp::Socket>(handle)
                .set_timeout(Some(Duration::from_secs(10)));
        }

        Stack {
            iface,
            dev,
            sockets,
            tcp_handle,
            tcp2_handle,
            tcp3_handle,
            tcp4_handle,
            icmp_handle,
            dns_handle,
            dhcp_handle: None,
            lease: None,
        }
    }

    /// Run one stack iteration: ingress, egress, timers. Every phase
    /// loops on this (docs/smoltcp-eval.md §4-M2).
    pub fn poll(&mut self) {
        self.iface
            .poll(clock::now(), &mut self.dev, &mut self.sockets);
    }

    /// Static addressing for the pre-DHCP phase: the smoke's
    /// NET_OK/PING_OK have always used slirp's guest address, and DHCP
    /// sources 0.0.0.0 regardless, so the DISCOVER is unaffected
    /// (docs/smoltcp-eval.md §7).
    pub fn set_static_ipv4(&mut self) {
        let guest = Ipv4Address::new(
            SLIRP_GUEST_IP[0],
            SLIRP_GUEST_IP[1],
            SLIRP_GUEST_IP[2],
            SLIRP_GUEST_IP[3],
        );
        let gateway = Ipv4Address::new(
            SLIRP_GATEWAY[0],
            SLIRP_GATEWAY[1],
            SLIRP_GATEWAY[2],
            SLIRP_GATEWAY[3],
        );
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::Ipv4(Ipv4Cidr::new(guest, 24)));
        });
        let _ = self.iface.routes_mut().add_default_ipv4_route(gateway);
    }

    /// ICMP echo roundtrip to the gateway: prints `NET_OK` the moment
    /// the gateway's ARP reply is sniffed (historical meaning kept —
    /// smoltcp resolved the neighbor itself) and `PING_OK` when the
    /// reply matches id, seq, payload and both addresses. Fatal on
    /// timeout (boot-time policy).
    pub fn prove_ping(&mut self) {
        const SEQ: u16 = 7;
        let payload = *b"pingtest";
        let gateway = Ipv4Address::new(
            SLIRP_GATEWAY[0],
            SLIRP_GATEWAY[1],
            SLIRP_GATEWAY[2],
            SLIRP_GATEWAY[3],
        );
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        let mut net_ok = false;
        let mut sent = false;
        loop {
            self.poll();
            if !net_ok && self.dev.saw_arp_reply {
                serial_println!("NET_OK"); // machine-checked by `cargo xtask smoke`
                net_ok = true;
            }
            if !sent && self.icmp_can_send() {
                if let Err(e) = self.icmp_send_echo(IpAddress::Ipv4(gateway), SEQ, &payload) {
                    fatal(e);
                }
                serial_println!(
                    "net: ICMP echo -> {}.{}.{}.{}",
                    SLIRP_GATEWAY[0],
                    SLIRP_GATEWAY[1],
                    SLIRP_GATEWAY[2],
                    SLIRP_GATEWAY[3]
                );
                sent = true;
            }
            if let Some(from) = self.icmp_take_echo_reply(SEQ, &payload) {
                if from != gateway {
                    fatal("echo reply addressed from the wrong host");
                }
                serial_println!(
                    "net: ICMP echo reply from {}.{}.{}.{} (payload intact)",
                    SLIRP_GATEWAY[0],
                    SLIRP_GATEWAY[1],
                    SLIRP_GATEWAY[2],
                    SLIRP_GATEWAY[3]
                );
                serial_println!("PING_OK"); // machine-checked by `cargo xtask smoke`
                return;
            }
            if clock::now_ms() > deadline {
                fatal("timeout waiting for ICMP echo reply");
            }
        }
    }

    /// Add the DHCP socket (**only after PING_OK** — R7: a fresh
    /// socket's first `poll()` reports `Deconfigured`, which would
    /// wipe the static address the first phases proved) and wait for
    /// a lease, applying it — smoltcp never applies configuration
    /// itself. The slirp values are asserted exactly as the old
    /// parser tests did (they are parser regression tests).
    /// Prints `DHCP_OK`.
    pub fn wait_lease(&mut self) {
        let handle = self.sockets.add(dhcpv4::Socket::new());
        self.dhcp_handle = Some(handle);
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            self.poll();
            // Extract owned copies first: the DHCP event borrows the
            // socket, and applying the lease borrows it again.
            let configured = match self.sockets.get_mut::<dhcpv4::Socket>(handle).poll() {
                Some(DhcpEvent::Configured(config)) => {
                    let want_ip = Ipv4Address::new(
                        SLIRP_GUEST_IP[0],
                        SLIRP_GUEST_IP[1],
                        SLIRP_GUEST_IP[2],
                        SLIRP_GUEST_IP[3],
                    );
                    let want_router = Ipv4Address::new(
                        SLIRP_GATEWAY[0],
                        SLIRP_GATEWAY[1],
                        SLIRP_GATEWAY[2],
                        SLIRP_GATEWAY[3],
                    );
                    let want_dns = Ipv4Address::new(
                        net::SLIRP_DNS[0],
                        net::SLIRP_DNS[1],
                        net::SLIRP_DNS[2],
                        net::SLIRP_DNS[3],
                    );
                    if config.address.address() != want_ip
                        || config.router != Some(want_router)
                        || config.dns_servers.first().copied() != Some(want_dns)
                    {
                        fatal("unexpected DHCP lease (parser regression vs slirp)");
                    }
                    let address = config.address;
                    let router = config.router;
                    let mut servers = [IpAddress::Ipv4(Ipv4Address::UNSPECIFIED); 1];
                    let server_count = config.dns_servers.len().min(servers.len());
                    for (slot, server) in servers.iter_mut().zip(config.dns_servers.iter()) {
                        *slot = IpAddress::Ipv4(*server);
                    }
                    let mut dns = [Ipv4Address::UNSPECIFIED; 4];
                    let dns_count = config.dns_servers.len().min(dns.len());
                    for (slot, server) in dns.iter_mut().zip(config.dns_servers.iter()) {
                        *slot = *server;
                    }
                    Some((address, router, servers, server_count, dns, dns_count))
                }
                // R7: the initial Deconfigured event of a fresh socket
                // must not clear the static address; there is no lease
                // to lose before the first Configured.
                Some(DhcpEvent::Deconfigured) | None => None,
            };
            if let Some((address, router, servers, server_count, dns, dns_count)) = configured {
                self.iface.update_ip_addrs(|addrs| {
                    addrs.clear();
                    let _ = addrs.push(IpCidr::Ipv4(address));
                });
                if let Some(router) = router {
                    let _ = self.iface.routes_mut().add_default_ipv4_route(router);
                }
                self.sockets
                    .get_mut::<dns::Socket>(self.dns_handle)
                    .update_servers(&servers[..server_count]);
                let lease = LeaseInfo {
                    address,
                    router,
                    dns,
                    dns_count,
                };
                self.lease = Some(lease);
                serial_println!("dhcp: lease {}", lease.address);
                match lease.router {
                    Some(router) => {
                        serial_println!("dhcp:   router {router} dns servers {}", lease.dns_count)
                    }
                    None => {
                        serial_println!("dhcp:   router (none) dns servers {}", lease.dns_count)
                    }
                }
                serial_println!("DHCP_OK"); // machine-checked by `cargo xtask smoke`
                return;
            }
            if clock::now_ms() > deadline {
                fatal("timeout waiting for DHCP lease (internet up?)");
            }
        }
    }

    /// One A-record query with a deadline: prints the old resolver's
    /// `dns: name -> ip` line and returns the first address (`None` =
    /// no answer — the shell must not die on a typo).
    pub fn resolve(&mut self, name: &str) -> Option<Ipv4Address> {
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        let query = {
            let dns_sock = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
            dns_sock
                .start_query(self.iface.context(), name, DnsQueryType::A)
                .ok()?
        };
        loop {
            self.poll();
            let dns_sock = self.sockets.get_mut::<dns::Socket>(self.dns_handle);
            match dns_sock.get_query_result(query) {
                Ok(addrs) => {
                    return match addrs.first() {
                        Some(IpAddress::Ipv4(ip)) => {
                            let ip = *ip; // matched through a reference
                            serial_println!("dns: {name} -> {ip}");
                            Some(ip)
                        }
                        _ => None,
                    };
                }
                Err(GetQueryResultError::Pending) => {
                    if clock::now_ms() > deadline {
                        dns_sock.cancel_query(query);
                        return None;
                    }
                }
                Err(GetQueryResultError::Failed) => {
                    dns_sock.cancel_query(query);
                    return None;
                }
            }
        }
    }

    /// Echo reply roundtrip to `ip` (shell `ping`): same identity as
    /// the boot proof, deadline-bounded, returns without panicking.
    pub fn ping(&mut self, ip: Ipv4Address) -> bool {
        const SEQ: u16 = 1;
        let payload = *b"pinging";
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        let mut sent = false;
        serial_println!("ping: ICMP echo -> {ip}");
        loop {
            self.poll();
            if !sent && self.icmp_can_send() {
                if self
                    .icmp_send_echo(IpAddress::Ipv4(ip), SEQ, &payload)
                    .is_err()
                {
                    serial_println!("ping: cannot send (icmp tx buffer busy)");
                    return false;
                }
                sent = true;
            }
            if let Some(from) = self.icmp_take_echo_reply(SEQ, &payload)
                && from == ip
            {
                serial_println!("ping: reply from {ip} ({} bytes)", payload.len());
                return true;
            }
            if clock::now_ms() > deadline {
                serial_println!("ping: no reply (timeout)");
                return false;
            }
        }
    }

    fn icmp_can_send(&mut self) -> bool {
        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !sock.is_open() {
            let _ = sock.bind(icmp::Endpoint::Ident(ECHO_ID));
        }
        sock.can_send()
    }

    fn icmp_send_echo(
        &mut self,
        to: IpAddress,
        seq: u16,
        payload: &[u8],
    ) -> Result<(), &'static str> {
        let caps = self.dev.capabilities();
        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !sock.is_open() {
            let _ = sock.bind(icmp::Endpoint::Ident(ECHO_ID));
        }
        let repr = Icmpv4Repr::EchoRequest {
            ident: ECHO_ID,
            seq_no: seq,
            data: payload,
        };
        let buf = sock
            .send(repr.buffer_len(), to)
            .map_err(|_| "icmp tx buffer full")?;
        let mut pkt = Icmpv4Packet::new_unchecked(buf);
        repr.emit(&mut pkt, &caps.checksum);
        Ok(())
    }

    /// Take one echo reply if it matches seq + payload exactly
    /// (checksum and bounds are verified by smoltcp's parser);
    /// strays are consumed and dropped so one poll cannot wedge.
    fn icmp_take_echo_reply(&mut self, seq: u16, payload: &[u8]) -> Option<Ipv4Address> {
        let caps = self.dev.capabilities();
        let sock = self.sockets.get_mut::<icmp::Socket>(self.icmp_handle);
        if !sock.can_recv() {
            return None;
        }
        let (data, from) = sock.recv().ok()?;
        let pkt = Icmpv4Packet::new_checked(data).ok()?;
        let repr = Icmpv4Repr::parse(&pkt, &caps.checksum).ok()?;
        match repr {
            Icmpv4Repr::EchoReply {
                ident,
                seq_no,
                data: got,
            } if ident == ECHO_ID && seq_no == seq && got == payload => {
                // IPv6 is not compiled in, so `IpAddress` has a single
                // variant — the destructure is irrefutable today.
                let IpAddress::Ipv4(ip) = from;
                Some(ip)
            }
            _ => None, // stray or mismatched echo: consumed and dropped
        }
    }

    /// The plain-HTTP proof (`TCP_OK`): connect to `:80`, one GET
    /// with `Connection: close`, read to the server's FIN, orderly
    /// close, and require the connection to reach TimeWait or Closed
    /// — the old smoke's full bidirectional-close proof (R5), now with
    /// smoltcp's retransmission, reassembly and Reno behind it.
    pub fn plain_get_smoke(&mut self, ip: Ipv4Address, host: &str) {
        const LOCAL_PORT: u16 = 49152;
        {
            let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp_handle);
            if let Err(e) = sock.connect(self.iface.context(), (ip, 80u16), LOCAL_PORT) {
                serial_println!("tcp: connect rejected: {e:?}");
                crate::halt();
            }
        }

        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            self.poll();
            if self.sockets.get::<tcp::Socket>(self.tcp_handle).state() == tcp::State::Established {
                break;
            }
            if clock::now_ms() > deadline {
                fatal("tcp connect timeout");
            }
        }
        serial_println!("tcp: connected to {ip}:80");

        let mut req = [0u8; 256];
        let Some(req_len) = http::build_get(&mut req, host, "/") else {
            fatal("GET request does not fit the buffer");
        };
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        let mut sent = 0usize;
        while sent < req_len {
            self.poll();
            match self
                .sockets
                .get_mut::<tcp::Socket>(self.tcp_handle)
                .send_slice(&req[sent..])
            {
                Ok(n) => sent += n,
                Err(_) => fatal("tcp send rejected (connection lost)"),
            }
            if clock::now_ms() > deadline {
                fatal("tcp send timeout");
            }
        }

        let mut resp = [0u8; 4096];
        let mut got = 0usize;
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            self.poll();
            let (can_recv, may_recv, queued, closed) = {
                let sock = self.sockets.get::<tcp::Socket>(self.tcp_handle);
                (
                    sock.can_recv(),
                    sock.may_recv(),
                    sock.recv_queue(),
                    sock.state() == tcp::State::Closed,
                )
            };
            if can_recv {
                if got >= resp.len() {
                    fatal("HTTP response exceeds the fixed buffer");
                }
                let n = self
                    .sockets
                    .get_mut::<tcp::Socket>(self.tcp_handle)
                    .recv_slice(&mut resp[got..])
                    .unwrap_or(0);
                got += n;
                continue;
            }
            if (!may_recv && queued == 0) || closed {
                break; // server FIN (or reset: validation below decides)
            }
            if clock::now_ms() > deadline {
                fatal("timeout waiting for the HTTP response");
            }
        }

        // A real HTTP status line and a complete header block, or we
        // did not get what we asked for. Same log-injection guard as
        // always: only a printable-ASCII line reaches the serial log.
        let resp = &resp[..got];
        if !resp.starts_with(b"HTTP/1.") || !http::headers_complete(resp) {
            fatal("response is not a complete HTTP/1.x header block");
        }
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

        // Orderly teardown: FIN, then require the full close.
        self.sockets.get_mut::<tcp::Socket>(self.tcp_handle).close();
        let deadline = clock::now_ms() + OP_DEADLINE_MS;
        loop {
            self.poll();
            let state = self.sockets.get::<tcp::Socket>(self.tcp_handle).state();
            if state == tcp::State::TimeWait || state == tcp::State::Closed {
                serial_println!("tcp: connection closed cleanly ({state})");
                serial_println!("TCP_OK"); // machine-checked by `cargo xtask smoke`
                return;
            }
            if clock::now_ms() > deadline {
                fatal("timeout closing connection (never reached TimeWait/Closed)");
            }
        }
    }
}
