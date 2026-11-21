//! smoltcp integration: the e1000 driver behind `phy::Device`, the
//! static storage the stack lives in, and the `Stack` handle the boot
//! chain drives. The evaluation, verified facts and the migration plan
//! live in `docs/smoltcp-eval.md`; this file is the M1 scaffolding —
//! linked and type-checked before the boot chain swaps over (M2).

// M1: nothing calls into this yet (the old chain still runs); the
// gate for this milestone is that smoltcp compiles into the kernel
// without disturbing the smoke. The allow goes away in M2.
#![allow(dead_code)]

use crate::clock;
use crate::e1000::E1000;
use net::SLIRP_GATEWAY;
use smoltcp::iface::{Config, Interface, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{dns, icmp};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress};

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

/// Everything the stack lives in, `const`-constructible for a
/// `static mut` (the same idiom as the TLS record buffers; measured
/// sizes in docs/smoltcp-eval.md §1.6 — ~11 KiB total).
pub struct Storage {
    pub slots: [SocketStorage<'static>; 4],
    pub tcp_rx: [u8; 4096],
    pub tcp_tx: [u8; 4096],
    pub icmp_rx_pkts: [icmp::PacketMetadata; 1],
    pub icmp_rx: [u8; 256],
    pub icmp_tx_pkts: [icmp::PacketMetadata; 1],
    pub icmp_tx: [u8; 256],
    pub dns_queries: [Option<dns::DnsQuery>; 1],
}

impl Storage {
    pub const fn new() -> Self {
        Storage {
            slots: [SocketStorage::EMPTY; 4],
            tcp_rx: [0; 4096],
            tcp_tx: [0; 4096],
            icmp_rx_pkts: [icmp::PacketMetadata::EMPTY; 1],
            icmp_rx: [0; 256],
            icmp_tx_pkts: [icmp::PacketMetadata::EMPTY; 1],
            icmp_tx: [0; 256],
            dns_queries: [None; 1],
        }
    }
}

/// The stack: interface + driver + socket set, all static-backed.
pub struct Stack {
    pub iface: Interface,
    pub dev: E1000Phy,
    pub sockets: SocketSet<'static>,
}

impl Stack {
    /// Wrap the initialized e1000. `random_seed` is **mandatory**
    /// (risk R1 of docs/smoltcp-eval.md): smoltcp draws TCP ISNs,
    /// source ports and DHCP transaction ids from an sPCG32 seeded
    /// here — default 0 would be a per-boot-constant ISN stream, a
    /// regression against the CSPRNG defense in `entropy.rs`.
    pub fn new(dev: E1000, storage: &'static mut Storage, random_seed: u64) -> Self {
        let mut dev = E1000Phy::new(dev);
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(dev.mac())));
        config.random_seed = random_seed;
        let iface = Interface::new(config, &mut dev, clock::now());
        let sockets = SocketSet::new(&mut storage.slots[..]);
        Stack {
            iface,
            dev,
            sockets,
        }
    }

    /// Run one stack iteration: ingress, egress, timers. Everything
    /// in the boot chain loops on this (docs/smoltcp-eval.md §4-M2).
    pub fn poll(&mut self) {
        self.iface
            .poll(clock::now(), &mut self.dev, &mut self.sockets);
    }
}
