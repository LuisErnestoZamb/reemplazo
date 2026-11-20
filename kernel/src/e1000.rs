//! Intel 82540EM ("e1000") driver — QEMU's NIC and therefore the
//! development target for the network stack (the MacBook's sky2 has no
//! QEMU model; see AGENTS.md).
//!
//! Every register offset, bit and init value here is verified against
//! sources, not remembered: Intel *8254x Family SW Developer's Manual*
//! (CTRL/EERD/RA), Linux `e1000_regs.h`/`e1000.h` (ring offsets, TCTL/
//! TIPG/RCTL values, descriptor structs, `E1000_COLLISION_THRESHOLD=15`,
//! `E1000_FDX_COLLISION_DISTANCE=64`), QEMU `hw/net/e1000.c` +
//! `e1000_regs.h` (EERD emulation, EEPROM words 0..2 = MAC,
//! `e1000x_reset_mac_addr`, RDH/RDT wrap), u-boot `e1000.h`
//! (`CTRL_SLU`, `RAH_AV`, `EEPROM_RW_*`), fable-os `drivers/net/e1000.c`
//! (ring bring-up order + RDT-reclaim pattern), charmOS docs (legacy
//! descriptor layouts).

use crate::pci::{Scan, read32, write32};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};
use pci::{CMD_BUS_MASTER, CMD_MEMORY_SPACE, E1000_82540EM, INTEL_VENDOR, mem_bar_address};

// --- Register offsets (Intel 8254x SDM / Linux e1000_regs.h) -----------
const CTRL: u32 = 0x00000; // Device Control - RW
const STATUS: u32 = 0x00008; // Device Status - RO
const ICR: u32 = 0x000C0; // Interrupt Cause Read - R/clr
const IMC: u32 = 0x000D8; // Interrupt Mask Clear - RW
const RCTL: u32 = 0x00100; // Receive Control - RW
const TCTL: u32 = 0x00400; // Transmit Control - RW
const TIPG: u32 = 0x00410; // TX Inter-Packet Gap - RW
const RDBAL: u32 = 0x02800; // RX Descriptor Base Address Low
const RDBAH: u32 = 0x02804; // RX Descriptor Base Address High
const RDLEN: u32 = 0x02808; // RX Descriptor Length (multiple of 128)
const RDH: u32 = 0x02810; // RX Descriptor Head
const RDT: u32 = 0x02818; // RX Descriptor Tail
const TDBAL: u32 = 0x03800; // TX Descriptor Base Address Low
const TDBAH: u32 = 0x03804; // TX Descriptor Base Address High
const TDLEN: u32 = 0x03808; // TX Descriptor Length (multiple of 128)
const TDH: u32 = 0x03810; // TX Descriptor Head
const TDT: u32 = 0x03818; // TX Descriptor Tail
const EERD: u32 = 0x00014; // EEPROM Read - RW
const RAL: u32 = 0x05400; // Receive Address Low 0 - RW
const RAH: u32 = 0x05404; // Receive Address High 0 - RW

// --- CTRL bits (u-boot e1000.h) ---------------------------------------
const CTRL_SLU: u32 = 0x0000_0040; // Set Link Up (RW)

// --- EERD bits (QEMU e1000_regs.h: START=1, DONE=0x10, ADDR<<8) -------
const EERD_START: u32 = 0x1;
const EERD_DONE: u32 = 0x10;
const EERD_ADDR_SHIFT: u32 = 8;
const EERD_DATA_SHIFT: u32 = 16;

// --- RAH bits (u-boot e1000.h) ----------------------------------------
const RAH_AV: u32 = 0x8000_0000; // Address Valid

// --- TCTL (Linux e1000.h: EN=2, PSP=8, CT=15<<4, COLD=64<<12) --------
// = 0x000400FA — the classic full-duplex value (matches fable-os).
const TCTL_EN: u32 = 0x2;
const TCTL_PSP: u32 = 0x8;
const TCTL_VALUE: u32 = TCTL_EN | TCTL_PSP | (15 << 4) | (64 << 12);
// TIPG: IPGT=10, IPGR1=8, IPGR2=6 (Linux E1000_TIPG_IPGT_1000 etc.)
// = 0x0060200A.
const TIPG_VALUE: u32 = 10 | (8 << 10) | (6 << 20);

// --- RCTL (Linux e1000.h: EN=0x2 — note, *not* bit 0 — BAM, SECRC) ---
const RCTL_EN: u32 = 0x0000_0002;
const RCTL_BAM: u32 = 0x0000_8000; // Broadcast accept (needed for DHCP later)
const RCTL_SECRC: u32 = 0x0400_0000; // Strip Ethernet CRC
// BSIZE bits17:16 = 0 → 2048-byte RX buffers (default).
const RCTL_VALUE: u32 = RCTL_EN | RCTL_BAM | RCTL_SECRC;

// --- Legacy TX descriptor cmd byte (Linux e1000_defines.h) ------------
// CMD_EOP=0x01000000, CMD_IFCS=0x02000000, CMD_RS=0x08000000 live in
// the top byte of the length/CMD dword → byte offset 11.
const TXD_CMD: u8 = 0x01 | 0x02 | 0x08; // EOP | IFCS | Report Status
/// DD (Descriptor Done) status bit, TX and RX (Linux e1000_defines.h).
const STATUS_DD: u8 = 0x01;

/// Descriptors per ring: 16 × 16 B = 256 B (multiple of 128 ✓ and of
/// the 8-descriptor multiple the hardware requires).
const N_DESC: usize = 16;
/// Bytes usable per TX/RX buffer (RX capped by RCTL.BSIZE = 2048; we
/// allocate full 4 KiB frames anyway).
const BUF_BYTES: usize = 4096;
/// Poll budgets (spins). TCG answers in microseconds; these bound the
/// smoke test's failure path to ≈1–2 s instead of hanging forever.
const TX_POLLS: u32 = 10_000_000;
const RX_POLLS: u32 = 100_000_000;

/// Poll attempts for an EEPROM read (QEMU answers immediately; real
/// silicon takes microseconds — spin, never sleep: interrupts are off).
const EEPROM_POLLS: u32 = 100_000;

// --- Descriptor layouts (Linux `struct e1000_{tx,rx}_desc`, charmOS) --
#[repr(C)]
struct TxDesc {
    buffer: u64,
    length: u16,
    cso: u8,
    cmd: u8,
    status: u8,
    css: u8,
    special: u16,
}

#[repr(C)]
struct RxDesc {
    buffer: u64,
    length: u16,
    csum: u16,
    status: u8,
    errors: u8,
    special: u16,
}

// Layout is a hardware ABI: catch compiler surprises at compile time.
const _: () = assert!(core::mem::size_of::<TxDesc>() == 16);
const _: () = assert!(core::mem::size_of::<RxDesc>() == 16);

fn mmio_read32(base: u64, reg: u32) -> u32 {
    // SAFETY: `base` is a PCI memory BAR checked to be < 4 GiB in `init`,
    // so it lies inside the entry.S identity map; `reg` is a 4-byte
    // aligned register offset and the access is a volatile device read.
    unsafe { core::ptr::read_volatile((base + u64::from(reg)) as *const u32) }
}

fn mmio_write32(base: u64, reg: u32, val: u32) {
    // SAFETY: same contract as `mmio_read32`.
    unsafe { core::ptr::write_volatile((base + u64::from(reg)) as *mut u32, val) }
}

/// Read one 16-bit EEPROM word through EERD. `None` on poll timeout.
fn eeprom_read(base: u64, word: u8) -> Option<u16> {
    mmio_write32(
        base,
        EERD,
        (u32::from(word) << EERD_ADDR_SHIFT) | EERD_START,
    );
    for _ in 0..EEPROM_POLLS {
        let eerd = mmio_read32(base, EERD);
        if eerd & EERD_DONE != 0 {
            return Some((eerd >> EERD_DATA_SHIFT) as u16);
        }
        core::hint::spin_loop();
    }
    None // timeout: EEPROM did not answer
}

/// MAC from EEPROM words 0..2 (Intel manual: the IA address lives there;
/// QEMU fills them from the NIC MAC, little-endian per word).
fn mac_from_eeprom(base: u64) -> Option<[u8; 6]> {
    let mut mac = [0u8; 6];
    for word_idx in 0..3u8 {
        let word = eeprom_read(base, word_idx)?;
        let slot = usize::from(word_idx) * 2;
        mac[slot] = word as u8; // low byte = first on the wire
        mac[slot + 1] = (word >> 8) as u8;
    }
    Some(mac)
}

/// MAC from RAL/RAH (the IA address is loaded there on reset — QEMU's
/// `e1000x_reset_mac_addr` and Intel manual §2.5 agree).
fn mac_from_rar(base: u64) -> Option<[u8; 6]> {
    let rah = mmio_read32(base, RAH);
    if rah & RAH_AV == 0 {
        return None;
    }
    let ral = mmio_read32(base, RAL);
    Some([
        ral as u8,
        (ral >> 8) as u8,
        (ral >> 16) as u8,
        (ral >> 24) as u8,
        rah as u8,
        (rah >> 8) as u8,
    ])
}

/// Non-zero, not broadcast, unicast (I/G bit clear).
fn mac_is_sane(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && *mac != [0xFF; 6] && mac[0] & 1 == 0
}

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: e1000: {msg}");
    crate::halt()
}

/// Hand out one physical frame as a buffer; identity map makes phys == virt.
fn alloc_frame(msg: &'static str) -> *mut u8 {
    match crate::memory::alloc() {
        Some(frame) => frame.start_phys() as *mut u8,
        None => fatal(msg),
    }
}

/// A probed, enabled e1000 with live TX/RX descriptor rings.
///
/// The struct owns raw pointers into DMA memory shared with the device;
/// access goes through volatile reads/writes only (never Rust references
/// to hardware-owned memory). Boot code is single-threaded.
pub struct E1000 {
    mmio: u64,
    mac: [u8; 6],
    tx_descs: *mut TxDesc,
    rx_descs: *mut RxDesc,
    tx_buffers: [*mut u8; N_DESC],
    rx_buffers: [*mut u8; N_DESC],
    tx_next: usize, // descriptor to submit next
    rx_next: usize, // descriptor to poll next
}

/// Probe, enable, read the MAC, bring up the rings, verify with
/// `E1000_OK`. Returns `None` when the NIC is absent (real hardware has
/// sky2, not e1000 — the boot must continue there); parks on a broken
/// device.
pub fn init(scan: &Scan) -> Option<E1000> {
    let dev = scan.find(INTEL_VENDOR, E1000_82540EM)?;
    serial_println!("e1000: found at {}", dev.location);
    let loc = dev.location;

    // BARs (offset 0x10/0x14), then enable memory + bus master (PCI cmd).
    let bar0 = read32(loc, 0x10);
    let bar1 = read32(loc, 0x14);
    let Some(mmio) = mem_bar_address(bar0, bar1) else {
        fatal("memory BAR missing or unassigned");
    };
    if mmio >= (1u64 << 32) {
        // entry.S identity-maps 4 GiB only — honest constraint, not a guess.
        fatal("memory BAR is above 4 GiB (outside the identity map)");
    }
    serial_println!("e1000: mmio {mmio:#010x}");

    let cmd_dword = read32(loc, 0x04);
    let want = (CMD_MEMORY_SPACE | CMD_BUS_MASTER) as u32;
    write32(
        loc,
        0x04,
        (cmd_dword & 0xFFFF_0000) | (cmd_dword as u16 | want as u16) as u32,
    );
    let cmd_after = read32(loc, 0x04) as u16;
    if cmd_after & want as u16 != want as u16 {
        fatal("could not enable memory space + bus master");
    }

    // Mask every card-side interrupt and drain latched causes: this
    // driver polls, and only IRQ0 (PIT) is unmasked on the PIC anyway.
    mmio_write32(mmio, IMC, 0xFFFF_FFFF);
    let _ = mmio_read32(mmio, ICR);

    // Config: SLU (standard for copper PHYs; QEMU stores it harmlessly).
    // We deliberately do NOT assert on CTRL: QEMU ships with SLU already
    // set, so a write-back check there would pass even with broken MMIO.
    // The EEPROM read below is the real write-path proof: EERD only
    // returns DONE+data if our START write actually reached the device.
    let ctrl = mmio_read32(mmio, CTRL);
    mmio_write32(mmio, CTRL, ctrl | CTRL_SLU);
    let status = mmio_read32(mmio, STATUS);
    serial_println!(
        "e1000: CTRL {:#010x} (SLU set), STATUS {status:#010x}",
        mmio_read32(mmio, CTRL)
    );

    // MAC: EEPROM is authoritative (Intel manual); RAL/RAH (loaded on
    // reset by QEMU) cross-checks the decode of both.
    let mac = match mac_from_eeprom(mmio) {
        Some(mac) => mac,
        None => fatal("EEPROM read timed out — EERD write path broken?"),
    };
    match mac_from_rar(mmio) {
        Some(rar) if rar != mac => fatal("EEPROM and RAL/RAH disagree (decode bug?)"),
        Some(_) => serial_println!("e1000: RAL/RAH agrees with EEPROM"),
        None => serial_println!("e1000: RAL/RAH invalid (AV clear) — EEPROM authoritative"),
    }
    if !mac_is_sane(&mac) {
        fatal("MAC is zero/broadcast/multicast");
    }
    serial_println!(
        "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    // Program the unicast filter explicitly (QEMU already did on reset,
    // but a driver must not depend on that): same byte order as QEMU's
    // `e1000x_reset_mac_addr`.
    let ral = u32::from_le_bytes([mac[0], mac[1], mac[2], mac[3]]);
    let rah = u32::from_le_bytes([mac[4], mac[5], 0, 0]) | RAH_AV;
    mmio_write32(mmio, RAL, ral);
    mmio_write32(mmio, RAH, rah);

    // --- TX ring -------------------------------------------------------
    let tx_descs = alloc_frame("out of frames (TX ring)").cast::<TxDesc>();
    let mut tx_buffers = [core::ptr::null_mut(); N_DESC];
    for (i, buf) in tx_buffers.iter_mut().enumerate() {
        *buf = alloc_frame("out of frames (TX buffer)");
        // SAFETY: unique fresh frame; desc i lives in the ring frame
        // (16 × 16 B fits its 4 KiB); identity-mapped and 16-byte
        // aligned (4 KiB frame base).
        unsafe {
            write_volatile(
                tx_descs.add(i),
                TxDesc {
                    buffer: *buf as u64,
                    length: 0,
                    cso: 0,
                    cmd: 0,
                    status: 0,
                    css: 0,
                    special: 0,
                },
            );
        }
    }
    mmio_write32(mmio, TDBAL, tx_descs as u64 as u32);
    mmio_write32(mmio, TDBAH, (tx_descs as u64 >> 32) as u32);
    mmio_write32(
        mmio,
        TDLEN,
        (N_DESC * core::mem::size_of::<TxDesc>()) as u32,
    );
    mmio_write32(mmio, TDH, 0);
    mmio_write32(mmio, TDT, 0);
    mmio_write32(mmio, TCTL, TCTL_VALUE);
    mmio_write32(mmio, TIPG, TIPG_VALUE);

    // --- RX ring -------------------------------------------------------
    let rx_descs = alloc_frame("out of frames (RX ring)").cast::<RxDesc>();
    let mut rx_buffers = [core::ptr::null_mut(); N_DESC];
    for (i, buf) in rx_buffers.iter_mut().enumerate() {
        *buf = alloc_frame("out of frames (RX buffer)");
        // SAFETY: as for the TX ring above.
        unsafe {
            write_volatile(
                rx_descs.add(i),
                RxDesc {
                    buffer: *buf as u64,
                    length: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                },
            );
        }
    }
    mmio_write32(mmio, RDBAL, rx_descs as u64 as u32);
    mmio_write32(mmio, RDBAH, (rx_descs as u64 >> 32) as u32);
    mmio_write32(
        mmio,
        RDLEN,
        (N_DESC * core::mem::size_of::<RxDesc>()) as u32,
    );
    mmio_write32(mmio, RDH, 0);
    // Tail = last descriptor we handed to the hardware (QEMU computes
    // available descriptors as RDT - RDH with wrap; fable-os uses N-1).
    mmio_write32(mmio, RDT, (N_DESC - 1) as u32);
    mmio_write32(mmio, RCTL, RCTL_VALUE);

    serial_println!(
        "e1000: rings up — {N_DESC} TX + {N_DESC} RX descriptors, TCTL {TCTL_VALUE:#010x}, RCTL {RCTL_VALUE:#010x}"
    );
    serial_println!("E1000_OK"); // machine-checked by `cargo xtask smoke`

    Some(E1000 {
        mmio,
        mac,
        tx_descs,
        rx_descs,
        tx_buffers,
        rx_buffers,
        tx_next: 0,
        rx_next: 0,
    })
}

impl E1000 {
    /// Send one Ethernet frame, waiting for the descriptor's DD bit
    /// (synchronous TX — fine at boot, replaced by queueing later).
    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > BUF_BYTES {
            return Err("frame larger than the TX buffer");
        }
        let idx = self.tx_next;
        let buf = self.tx_buffers[idx];
        // SAFETY: `buf` is our private frame; `frame.len() <= BUF_BYTES`
        // was checked, so the copy cannot leave the 4 KiB frame.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), buf, frame.len());
        }
        let desc = TxDesc {
            buffer: buf as u64,
            length: frame.len() as u16,
            cso: 0,
            cmd: TXD_CMD,
            status: 0,
            css: 0,
            special: 0,
        };
        // SAFETY: our ring frame (see init); descriptor idx is ours until
        // TDT publishes it below.
        unsafe {
            write_volatile(self.tx_descs.add(idx), desc);
        }
        // Descriptors must hit memory before the device sees TDT.
        fence(Ordering::SeqCst);
        mmio_write32(self.mmio, TDT, ((idx + 1) % N_DESC) as u32);

        for _ in 0..TX_POLLS {
            // SAFETY: volatile read of device-updated status in our ring.
            let d = unsafe { read_volatile(self.tx_descs.add(idx)) };
            if d.status & STATUS_DD != 0 {
                self.tx_next = (idx + 1) % N_DESC;
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("TX descriptor never reported DD")
    }

    /// Poll for one received frame; copies it into `buf` and returns the
    /// length, or `None` when nothing has arrived yet.
    pub fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        let idx = self.rx_next;
        // SAFETY: our ring; the NIC only writes length/csum/status after
        // DMA-ing the packet into our buffer.
        let d = unsafe { read_volatile(self.rx_descs.add(idx)) };
        if d.status & STATUS_DD == 0 {
            return None;
        }
        let n = core::cmp::min(usize::from(d.length), buf.len());
        // SAFETY: rx_buffers[idx] is our private 4 KiB frame; the NIC
        // writes at most RCTL.BSIZE (2048) bytes into it, and `buf` is
        // at least `n` bytes (min above).
        unsafe {
            core::ptr::copy_nonoverlapping(self.rx_buffers[idx], buf.as_mut_ptr(), n);
        }
        // Reclaim: restore the descriptor (buffer_addr survives anyway,
        // but a full rewrite is cheaper to reason about) and hand it
        // back by pointing RDT at it — the pattern fable-os/QEMU use.
        // SAFETY: as above; the device no longer owns descriptor idx.
        unsafe {
            write_volatile(
                self.rx_descs.add(idx),
                RxDesc {
                    buffer: self.rx_buffers[idx] as u64,
                    length: 0,
                    csum: 0,
                    status: 0,
                    errors: 0,
                    special: 0,
                },
            );
        }
        fence(Ordering::SeqCst);
        mmio_write32(self.mmio, RDT, idx as u32);
        self.rx_next = (idx + 1) % N_DESC;
        Some(n)
    }

    /// End-to-end proof of the TX/RX path: transmit an ARP request for
    /// slirp's gateway, require slirp's ARP reply back on the RX ring,
    /// print `NET_OK`, and return the peer's MAC (addressed by the ICMP
    /// test that follows).
    pub fn selftest(&mut self) -> [u8; 6] {
        let mut req = [0u8; 64];
        let len = match net::build_arp_request(
            &mut req,
            self.mac,
            net::SLIRP_GUEST_IP,
            net::SLIRP_GATEWAY,
        ) {
            Some(n) => n,
            None => fatal("cannot build ARP request (buffer bug?)"),
        };
        if let Err(e) = self.transmit(&req[..len]) {
            fatal(e);
        }
        serial_println!("e1000: TX {len} bytes ARP request ->10.0.2.2, descriptor DD set");

        let mut rx = [0u8; 2048];
        let mut got = None;
        for _ in 0..RX_POLLS {
            if let Some(n) = self.receive(&mut rx) {
                got = Some(n);
                break;
            }
            core::hint::spin_loop();
        }
        let Some(n) = got else {
            fatal("timeout waiting for ARP reply (is the user-mode netdev attached?)");
        };
        let frame = &rx[..n];
        if net::ethertype(frame) != Some(net::ETHERTYPE_ARP) {
            fatal("received a non-ARP frame");
        }
        if net::arp_opcode(frame) != Some(net::ARP_REPLY) {
            fatal("ARP frame is not a reply");
        }
        if net::dst_mac(frame) != Some(self.mac) {
            fatal("frame not addressed to our MAC (filter broken?)");
        }
        let Some(peer) = net::arp_sender_mac(frame) else {
            fatal("ARP reply carries no sender address");
        };
        if peer == self.mac {
            fatal("ARP sender resolved to our own MAC");
        }
        serial_println!("e1000: RX {n} bytes ARP reply from slirp");
        serial_println!("NET_OK"); // machine-checked by `cargo xtask smoke`
        peer
    }

    /// ICMP echo roundtrip to the ARP-resolved peer: proves the IPv4
    /// path end-to-end (both internet checksums are validated on the
    /// reply). Prints `PING_OK`.
    pub fn ping_test(&mut self, peer_mac: [u8; 6]) {
        const PING_ID: u16 = 0x5252;
        const PING_SEQ: u16 = 7;
        const PING_PAYLOAD: [u8; 8] = *b"pingtest";

        let mut req = [0u8; 128];
        let src = net::Endpoint::new(self.mac, net::SLIRP_GUEST_IP);
        let dst = net::Endpoint::new(peer_mac, net::SLIRP_GATEWAY);
        let len = match net::build_icmp_echo(&mut req, src, dst, PING_ID, PING_SEQ, &PING_PAYLOAD) {
            Some(n) => n,
            None => fatal("cannot build ICMP echo (buffer bug?)"),
        };
        if let Err(e) = self.transmit(&req[..len]) {
            fatal(e);
        }
        serial_println!("e1000: TX {len} bytes ICMP echo ->10.0.2.2");

        // Poll until a *matching* reply arrives (skip stray frames).
        let mut rx = [0u8; 2048];
        let mut spins = 0u32;
        let reply = loop {
            if spins >= RX_POLLS {
                fatal("timeout waiting for ICMP echo reply");
            }
            spins += 1;
            if let Some(n) = self.receive(&mut rx) {
                if let Some(reply) = net::parse_icmp_echo_reply(&rx[..n]) {
                    break reply;
                }
            } else {
                core::hint::spin_loop();
            }
        };
        if reply.src_ip != net::SLIRP_GATEWAY || reply.dst_ip != net::SLIRP_GUEST_IP {
            fatal("echo reply addressed to the wrong hosts");
        }
        if (reply.id, reply.seq) != (PING_ID, PING_SEQ) {
            fatal("echo reply id/seq mismatch");
        }
        if reply.payload != PING_PAYLOAD {
            fatal("echo reply payload corrupted");
        }
        serial_println!(
            "e1000: ICMP echo reply from 10.0.2.2 (id={:#06x} seq={}, payload intact)",
            reply.id,
            reply.seq
        );
        serial_println!("PING_OK"); // machine-checked by `cargo xtask smoke`
    }
}
