//! Pure wire/register logic for the Marvell 88E8053 ("Yukon-2 EC")
//! sky2 driver — the MacBook2,1 NIC (AGENTS.md, docs/hardware.md §1).
//!
//! This crate holds everything about the chip that can be decided
//! without touching hardware: list-element (descriptor) layouts and
//! flags, status-ring entry parsing, SMI/MDIO register encoding, PHY
//! identification, MAC validation, link/flow-control decoding and the
//! composition of the bring-up register values. The MMIO `unsafe` glue
//! lives in `kernel/src/sky2.rs` (the project's `unsafe` budget rule).
//!
//! **Sources — no register here is remembered or invented:**
//!
//! - Linux v6.6 `drivers/net/ethernet/marvell/sky2.c` and `sky2.h`,
//!   fetched from the pinned URLs
//!   `https://raw.githubusercontent.com/torvalds/linux/v6.6/drivers/net/ethernet/marvell/sky2.{c,h}`
//!   (SHA-256 `3fe71637…b4fbfb51` / `5a4e48ab…feb49a14b`; line numbers
//!   in the `sky2.c:NNNN` / `sky2.h:NNNN` comments refer to those
//!   exact files).
//! - Measured facts about the real machine (2026-11-21, SSH from the
//!   running Debian install): PCI `11ab:4362` rev 22 = Yukon-2 EC
//!   revision 2, EEPROM MAC `00:19:e3:39:f4:a2`, link 1000 Mbps full
//!   duplex with flow control — `docs/hardware.md` §1.1.
//!
//! Dependency-policy note (recorded in the commit): this is
//! protocol/driver glue over documented hardware, not cryptography, so
//! it is written from scratch under exception (a) — there is no
//! maintained `no_std` sky2 crate, and the register-level truth
//! (sky2.c) is the best possible reference. Zero dependencies,
//! `no_std`, `forbid(unsafe_code)`, adversarially host-tested.
//!
//! **Deviation from the milestone sketch:** the sketch said "EEPROM
//! checksum/validation". sky2.c has *no* EEPROM controller access at
//! all — the chip's EEPROM loader writes the MAC into `B2_MAC_1`, and
//! Linux reads exactly that ([sky2.c:4665]); `ethtool -e` on this NIC
//! reads PCI **VPD**, not a chip EEPROM ([sky2.c:4271-4283]), and no
//! checksum over it is defined anywhere in sky2.c. What exists and is
//! validated instead is the MAC-address sanity check Linux performs
//! after the `B2_MAC_1` read ([sky2.c:4671]) — see [`mac_is_sane`].

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

// ---------------------------------------------------------------------------
// List elements (8-byte descriptors): sky2.h:2104-2149, 2164-2176
// ---------------------------------------------------------------------------

/// Owner bit in the `opcode` byte: the driver sets it when it hands an
/// element to the chip, the chip clears it when done (sky2.h:2115).
pub const HW_OWNER: u8 = 1 << 7;
/// End-of-packet flag in the `ctrl` byte of the last TX data element
/// (sky2.h:2111).
pub const EOP: u8 = 1 << 7;

/// Load the upper 32 bits of the DMA data address (sky2.h:2126).
pub const OP_ADDR64: u8 = 0x21;
/// TX packet fragment / RX buffer-to-fill (sky2.h:2135).
pub const OP_PACKET: u8 = 0x41;
/// RX status entry: one received frame (sky2.h:2140).
pub const OP_RXSTAT: u8 = 0x60;
/// TX completion: report of the consumed ring index (sky2.h:2147).
pub const OP_TXINDEXLE: u8 = 0x68;

/// One 8-byte list element (sky2.h:2164-2176, `struct sky2_tx_le` /
/// `sky2_rx_le` — both have the same layout).
///
/// Layout is a hardware ABI: `#[repr(C)]` plus a compile-time size
/// check (same discipline as the e1000 descriptors). The kernel writes
/// and reads these through volatile accesses; on x86-64 (little
/// endian) the in-memory bytes are the little-endian wire encoding.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Le {
    /// Low 32 bits of the host buffer address (high bits travel in a
    /// separate `OP_ADDR64` element).
    pub addr: u32,
    /// Byte count: TX fragment length / RX buffer length.
    pub length: u16,
    /// Per-element control flags ([`EOP`] on the last TX element).
    pub ctrl: u8,
    /// Operation | [`HW_OWNER`].
    pub opcode: u8,
}

// Layout is a hardware ABI: catch compiler surprises at compile time.
const _: () = assert!(core::mem::size_of::<Le>() == 8);

impl Le {
    /// TX data element for a single-fragment frame (sky2.c:1959-1967:
    /// `OP_PACKET | HW_OWNER` with `ctrl |= EOP` on the last element
    /// — sky2.c:1978).
    pub const fn tx_packet(addr_low: u32, length: u16) -> Self {
        Le {
            addr: addr_low,
            length,
            ctrl: EOP,
            opcode: OP_PACKET | HW_OWNER,
        }
    }

    /// RX buffer element: "here is a buffer of `length` bytes"
    /// (sky2.c:1186-1197 `sky2_rx_add` with `OP_PACKET`, `ctrl = 0`).
    pub const fn rx_buffer(addr_low: u32, length: u16) -> Self {
        Le {
            addr: addr_low,
            length,
            ctrl: 0,
            opcode: OP_PACKET | HW_OWNER,
        }
    }

    /// Upper-address element: `addr` carries bits 63..32 of subsequent
    /// data-element addresses (sky2.c:1849-1856, sky2.h:2126).
    pub const fn addr64(addr_high: u32) -> Self {
        Le {
            addr: addr_high,
            length: 0,
            ctrl: 0,
            opcode: OP_ADDR64 | HW_OWNER,
        }
    }

    /// Still owned by the hardware? (Driver clears `opcode` after
    /// consuming a status element — sky2.c:2651.)
    pub const fn hw_owned(&self) -> bool {
        self.opcode & HW_OWNER != 0
    }
}

// ---------------------------------------------------------------------------
// Status-ring entries: sky2.h:2178-2183, parsing rules sky2.c:2587-2737
// ---------------------------------------------------------------------------

/// One decoded status-ring entry (sky2.h:2178-2183).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusEntry {
    /// `OP_RXSTAT`: frame received. `len` is the frame length when the
    /// status is trustworthy, `None` when the entry reports an error or
    /// a length mismatch — in both cases the driver re-submits the
    /// buffer, but only `Some` copies data out (sky2.c:2596-2640).
    Rx { len: Option<u16> },
    /// `OP_TXINDEXLE` (port 0): all TX ring slots below `next` are
    /// complete — the value the driver walks `tx_cons` to
    /// (sky2.c:2777-2784: `status & 0xfff` for port 0).
    TxComplete { next: u16 },
    /// Anything else (VLAN/checksum/RSS/unknown opcodes, or an RX entry
    /// for a second port we do not drive): consume and ignore
    /// (sky2.c:2715-2735 handles them; a lone port-0 chip never sees
    /// port 1, and our buffer tracking is port-0 only).
    Ignored,
}

/// `GMR_FS_LEN`, frame-length field of the RX status (sky2.h:1840).
const GMR_FS_LEN: u32 = 0x7fff << 16;
/// `GMR_FS_RX_OK`: good packet (sky2.h:1846).
const GMR_FS_RX_OK: u32 = 1 << 8;
/// `GMR_FS_ANY_ERR`: any of jabber/undersize/fragment/long/MII/bad-FC/
/// CRC/FIFO-overflow (sky2.h:1856-1859). Public because the kernel
/// writes it into `RX_GMF_FL_MSK` exactly as sky2.c:971 does.
pub const GMR_FS_ANY_ERR: u32 = 0x1 | 0x2 | 0x8 | 0x10 | 0x20 | 0x40 | 0x800 | 0x1000;
/// `CSS_LINK_BIT`: port number in the `css` byte (sky2.h:2160).
const CSS_LINK_BIT: u8 = 1 << 0;

/// Decode one 8-byte status element.
///
/// Returns `None` when the entry is absent (`opcode` lacks
/// [`HW_OWNER`] — the chip has not written it) or the byte string is
/// truncated; anything else decodes to a [`StatusEntry`] (unknown
/// opcodes become [`StatusEntry::Ignored`], never an error).
///
/// The RX validation mirrors `sky2_receive` [sky2.c:2596-2640]
/// exactly: drop on any error bit, drop unless `GMR_FS_RX_OK`, and
/// require the LE length to equal the length the MAC reports in the
/// status (a mismatch means truncated/garbled DMA data).
pub fn parse_status(bytes: &[u8]) -> Option<StatusEntry> {
    let opcode = *bytes.get(7)?;
    if opcode & HW_OWNER == 0 {
        return None; // not written (or already consumed) by hardware
    }
    let status = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let length = u16::from_le_bytes([bytes[4], bytes[5]]);
    let css = bytes[6];

    match opcode & !HW_OWNER {
        OP_RXSTAT => {
            // A port-1 entry would desynchronize our single port-0
            // buffer rotation; the chip is single-port, so this is
            // defensive only (sky2.c:2649: `css & CSS_LINK_BIT`).
            if css & CSS_LINK_BIT != 0 {
                return Some(StatusEntry::Ignored);
            }
            let count = ((status & GMR_FS_LEN) >> 16) as u16;
            let good =
                status & GMR_FS_ANY_ERR == 0 && status & GMR_FS_RX_OK != 0 && count == length;
            Some(StatusEntry::Rx {
                len: if good { Some(length) } else { None },
            })
        }
        OP_TXINDEXLE => Some(StatusEntry::TxComplete {
            next: (status & 0xfff) as u16, // port 0: sky2.c:2777
        }),
        _ => Some(StatusEntry::Ignored),
    }
}

// ---------------------------------------------------------------------------
// SMI (MDIO) register encoding: sky2.c:152-206, sky2.h:1820-1830
// ---------------------------------------------------------------------------

/// PHY device address field mask, bits 15..11 (sky2.h:1822).
const SMI_PHY_MSK: u16 = 0x1f << 11;
/// PHY register address field mask, bits 10..6 (sky2.h:1823).
const SMI_REG_MSK: u16 = 0x1f << 6;
/// OpCode read (0 = write), bit 5 (sky2.h:1824).
const SMI_OP_RD: u16 = 1 << 5;
/// Read-valid flag, bit 4 (sky2.h:1825).
const SMI_RD_VAL: u16 = 1 << 4;
/// Busy flag, bit 3 (sky2.h:1826).
const SMI_BUSY: u16 = 1 << 3;

/// Compose the `GM_SMI_CTRL` value for one SMI access
/// (`GM_SMI_CT_PHY_AD | GM_SMI_CT_REG_AD [| GM_SMI_CT_OP_RD]`,
/// sky2.c:154-155 / 177-178).
///
/// Out-of-range `phy`/`reg` are **masked**, exactly like the sky2.h
/// macros `GM_SMI_CT_PHY_AD`/`GM_SMI_CT_REG_AD` (sky2.h:1829-1830) —
/// they truncate rather than panic, because this value goes straight
/// into a hardware register.
pub const fn smi_ctrl(phy: u8, reg: u8, read: bool) -> u16 {
    let phy_part = ((phy as u16) << 11) & SMI_PHY_MSK;
    let reg_part = ((reg as u16) << 6) & SMI_REG_MSK;
    if read {
        phy_part | reg_part | SMI_OP_RD
    } else {
        phy_part | reg_part
    }
}

/// Poll condition for a completed SMI *read* (sky2.c:182-184: wait
/// until `GM_SMI_CT_RD_VAL` sets, then take `GM_SMI_DATA`).
pub const fn smi_read_done(ctrl: u16) -> bool {
    ctrl & SMI_RD_VAL != 0
}

/// Poll condition for an SMI *write* still in flight (sky2.c:164-166:
/// wait until `GM_SMI_CT_BUSY` clears).
pub const fn smi_busy(ctrl: u16) -> bool {
    ctrl & SMI_BUSY != 0
}

/// `ctrl == 0xffff` means the read path itself is dead (floating /
/// unmapped MMIO) — sky2.c:162-164 treats it as an I/O error, not a
/// timeout.
pub const fn smi_dead(ctrl: u16) -> bool {
    ctrl == 0xffff
}

// ---------------------------------------------------------------------------
// PHY identification: sky2.h:1214, 1223
// ---------------------------------------------------------------------------

/// Marvell OUI carried in `PHY_MARV_ID0` (sky2.h:1214).
pub const PHY_ID0_MARVELL: u16 = 0x0141;
/// `PHY_MARV_ID1` of the 88E1111-class PHY wired to a Yukon-EC
/// (88E8053) — what the MacBook should answer (sky2.h:1223).
pub const PHY_ID1_YUKON_EC: u16 = 0x0CC2;

/// Does `PHY_MARV_ID0` say "Marvell"? Anything else means the SMI
/// path is misconfigured (or the read returned garbage) — the kernel
/// fails closed on `false`.
pub const fn is_marvell_phy(id0: u16) -> bool {
    id0 == PHY_ID0_MARVELL
}

/// Is `PHY_MARV_ID1` the Yukon-EC part? Reported, not fatal: the
/// driver proceeds on any Marvell PHY and prints the numeric id
/// (sky2.c only cross-checks IDs inside a Yukon-XL workaround,
/// sky2.c:905-910).
pub const fn is_yukon_ec_phy(id1: u16) -> bool {
    id1 == PHY_ID1_YUKON_EC
}

// ---------------------------------------------------------------------------
// MAC address: sky2.c:4665-4678
// ---------------------------------------------------------------------------

/// A usable unicast address: not all-zero, not broadcast, I/G bit
/// clear (Linux `is_valid_ether_addr`, applied by sky2.c:4671 after
/// the `B2_MAC_1` read).
pub fn mac_is_sane(mac: &[u8; 6]) -> bool {
    *mac != [0; 6] && *mac != [0xFF; 6] && mac[0] & 1 == 0
}

/// IEEE 802 locally-administered bit (bit 1 of the first octet) —
/// printed as a note at probe time; never a hard error.
pub fn locally_administered(mac: &[u8; 6]) -> bool {
    mac[0] & 2 != 0
}

// ---------------------------------------------------------------------------
// Link status / flow control: sky2.c:2149-2293
// ---------------------------------------------------------------------------

/// `PHY_MARV_PHY_STAT` speed field (sky2.h:1356-1359).
const PS_SPEED_MSK: u16 = 3 << 14;
/// Speed field value "1000 Mbps" (sky2.h:1357).
const PS_SPEED_1000: u16 = 3 << 14;
/// Speed field value "100 Mbps" (sky2.h:1358).
const PS_SPEED_100: u16 = 1 << 14;
/// `PHY_M_PS_FULL_DUP` (sky2.h:1360).
const PS_FULL_DUP: u16 = 1 << 13;
/// `PHY_M_PS_SPDUP_RES`: auto-negotiation resolved (sky2.h:1362).
const PS_SPDUP_RES: u16 = 1 << 11;
/// `PHY_M_PS_LINK_UP` (sky2.h:1363).
const PS_LINK_UP: u16 = 1 << 10;

/// A resolved link (what `PHY_MARV_PHY_STAT` reports once
/// auto-negotiation completed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedLink {
    pub speed_mbps: u16,
    pub full_duplex: bool,
}

/// Decode `PHY_MARV_PHY_STAT`: `None` until the link is up *and*
/// speed/duplex resolved (the pair sky2.c:2327 and sky2.c:2257
/// check), `Some` afterwards. Speed decoding follows `sky2_phy_speed`
/// [sky2.c:2149-2169] — this driver only ever runs the copper
/// gigabit path, so the fibre shortcut and the non-gigabit branch are
/// not applicable to the 88E8053 (a copper part, sky2.c:3157-3163).
pub fn resolve_link(phystat: u16) -> Option<ResolvedLink> {
    if phystat & PS_SPDUP_RES == 0 || phystat & PS_LINK_UP == 0 {
        return None;
    }
    let speed_mbps = match phystat & PS_SPEED_MSK {
        PS_SPEED_1000 => 1000,
        PS_SPEED_100 => 100,
        _ => 10,
    };
    Some(ResolvedLink {
        speed_mbps,
        full_duplex: phystat & PS_FULL_DUP != 0,
    })
}

/// Flow-control mode negotiated by auto-negotiation (sky2.h
/// `enum flow_control`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControl {
    None,
    Tx,
    Rx,
    Both,
}

/// Pause-capability bits: `PHY_M_AN_PC`/`PHY_M_AN_ASP` (sky2.h:1268-1269)
/// are the same bit positions as IEEE `ADVERTISE_PAUSE_CAP`/`_ASYM`
/// that `sky2_autoneg_done` tests [sky2.c:2264-2277].
const AN_PAUSE_CAP: u16 = 1 << 10;
const AN_PAUSE_ASYM: u16 = 1 << 11;

/// Resolve flow control from our advertisement and the link
/// partner's, mirroring `sky2_autoneg_done` [sky2.c:2264-2277],
/// including its final rule for this chip family: half duplex below
/// 1 Gbps gets no flow control [sky2.c:2274-2276, the condition
/// `!(EC_U || EX)` holds for plain Yukon-EC].
pub fn flow_control(advert: u16, lpa: u16, link: ResolvedLink) -> FlowControl {
    let mut fc = FlowControl::None;
    if advert & AN_PAUSE_CAP != 0 {
        if lpa & AN_PAUSE_CAP != 0 {
            fc = FlowControl::Both;
        } else if advert & AN_PAUSE_ASYM != 0 {
            fc = FlowControl::Rx;
        }
    } else if advert & AN_PAUSE_ASYM != 0 && lpa & AN_PAUSE_CAP != 0 && lpa & AN_PAUSE_ASYM != 0 {
        fc = FlowControl::Tx;
    }
    if !link.full_duplex && link.speed_mbps < 1000 {
        fc = FlowControl::None;
    }
    fc
}

// ---------------------------------------------------------------------------
// Bring-up register-value composition (init table): sky2.c cited per fn
// ---------------------------------------------------------------------------

/// `PHY_MARV_AUNE_ADV` value: CSMA selector + all four copper speeds
/// (`sky2_supported_modes` advertises 10/100/1000 both duplexes,
/// sky2.c:3558-3570, 4623) + pause both directions (default
/// `flow_mode = FC_BOTH`, sky2.c:4619 → `copper_fc_adv[FC_BOTH] =
/// PHY_M_AN_PC | PHY_M_AN_ASP`, sky2.c:273-277, applied at
/// sky2.c:459-461). This is what makes the measured "1000 FD + flow
/// control" link (docs/hardware.md §1.1) the expected outcome.
pub const fn phy_advertisement() -> u16 {
    // PHY_AN_CSMA (sky2.h:1242) | PHY_M_AN_100_FD/100_HD/10_FD/10_HD
    // (sky2.h:1271-1274) | PHY_M_AN_PC | PHY_M_AN_ASP (sky2.h:1268-1269).
    const PHY_AN_CSMA: u16 = 1 << 0;
    const PHY_M_AN_100_FD: u16 = 1 << 8;
    const PHY_M_AN_100_HD: u16 = 1 << 7;
    const PHY_M_AN_10_FD: u16 = 1 << 6;
    const PHY_M_AN_10_HD: u16 = 1 << 5;
    PHY_AN_CSMA
        | PHY_M_AN_100_FD
        | PHY_M_AN_100_HD
        | PHY_M_AN_10_FD
        | PHY_M_AN_10_HD
        | AN_PAUSE_CAP
        | AN_PAUSE_ASYM
}

/// `PHY_MARV_1000T_CTRL` value: advertise 1000 Mbps full + half
/// (`PHY_M_1000C_AFD | PHY_M_1000C_AHD`, sky2.c:413-416,
/// sky2.h:1300-1301).
pub const fn phy_1000t_ctrl() -> u16 {
    (1 << 9) | (1 << 8)
}

/// `PHY_MARV_CTRL` value that restarts auto-negotiation:
/// `PHY_CT_RESET | PHY_CT_ANE | PHY_CT_RE_CFG` (sky2.c:408, 468-469,
/// sky2.h:1176/1179/1182).
pub const fn phy_ctrl_autoneg() -> u16 {
    (1 << 15) | (1 << 12) | (1 << 9)
}

/// Read-modify-write for `PHY_MARV_EXT_CTRL` on a Yukon-EC with
/// auto-speed (sky2.c:331-349): clear the downshift-counter and MAC
/// clock-speed fields, set the 25 MHz MAC interface clock
/// (`MAC_TX_CLK_25_MHZ = 7`, sky2.h:1451), and for Yukon-EC enable
/// downshift with a 3x counter (`PHY_M_EC_DSC_2(2) |
/// PHY_M_EC_DOWN_S_ENA`).
pub const fn phy_ext_ctrl_ec(prev: u16) -> u16 {
    const M_DSC_MSK: u16 = 3 << 10; // sky2.h:1412
    const S_DSC_MSK: u16 = 3 << 8; // sky2.h:1414
    const MAC_S_MSK: u16 = 7 << 4; // sky2.h:1421
    const MAC_S_25: u16 = (7 << 4) & MAC_S_MSK; // PHY_M_EC_MAC_S(7), sky2.h:1435
    const DSC_2_3X: u16 = (2 << 9) & (7 << 9); // PHY_M_EC_DSC_2(2), sky2.h:1433
    const DOWN_S_ENA: u16 = 1 << 8; // sky2.h:1418
    (prev & !(M_DSC_MSK | S_DSC_MSK | MAC_S_MSK)) | MAC_S_25 | DSC_2_3X | DOWN_S_ENA
}

/// Read-modify-write for `PHY_MARV_PHY_CTRL` on a copper gigabit PHY
/// (sky2.c:365-377): disable energy-detect, enable automatic
/// MDI/MDI-X crossover (`PHY_M_PC_MDI_XMODE(PHY_M_PC_ENA_AUTO)` =
/// 3<<5).
pub const fn phy_specific_ctrl_gig(prev: u16) -> u16 {
    const EN_DET_MSK: u16 = 3 << 8; // sky2.h:1336
    const MDIX_MSK: u16 = 3 << 5; // sky2.h:1339
    const MDIX_AUTO: u16 = (3 << 5) & MDIX_MSK; // PHY_M_PC_ENA_AUTO, sky2.h:1353
    (prev & !EN_DET_MSK) | MDIX_AUTO
}

/// RX data-buffer size programmed into every RX element: the frame
/// size (`mtu + ETH_HLEN + VLAN_HLEN`, i.e. `mtu + 18`) rounded up
/// to a multiple of 8 — `sky2.c:1140-1147` `sky2_get_rx_data_size`.
pub const fn rx_data_size(mtu: u16) -> u16 {
    let size = mtu as u32 + 18;
    size.div_ceil(8).saturating_mul(8) as u16
}

/// RX oversize-truncation threshold `(roundup(mtu + 18, 8) - 8) / 4`,
/// or `None` when it exceeds the register's 9 bits (0x1FF) —
/// sky2.c:1140-1147 + the caller's bound check at sky2.c:1555-1571
/// ("The receiver hangs if it receives frames larger than the packet
/// buffer").
pub const fn rx_truncation_threshold(mtu: u16) -> Option<u16> {
    let size = rx_data_size(mtu) as u32;
    let thresh = (size - 8) / 4;
    if thresh > 0x1ff {
        None
    } else {
        Some(thresh as u16)
    }
}

/// How the chip's internal RAM buffer is split between the RX and TX
/// queues (sky2.c:1675-1688 `sky2_hw_up`): RX gets the first
/// `8 + 2*(ram-16)/3` KiB when the buffer is ≥ 16 KiB, else half;
/// TX gets the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamPartition {
    pub rx_space_kb: u16,
    pub tx_space_kb: u16,
}

/// Partition the RAM buffer reported in `B2_E_0` (in 4 KiB blocks,
/// sky2.c:3222 — the caller converts to KiB first). `None` for an
/// empty buffer (`B2_E_0 == 0` ⇒ no RAM buffer at all, sky2.c:1673).
pub const fn ram_buffer_layout(ram_kb: u16) -> Option<RamPartition> {
    if ram_kb == 0 {
        return None;
    }
    let rx = if ram_kb < 16 {
        ram_kb / 2
    } else {
        8 + (2 * (ram_kb - 16)) / 3
    };
    Some(RamPartition {
        rx_space_kb: rx,
        tx_space_kb: ram_kb - rx,
    })
}

/// RAM-buffer thresholds for one queue, in the register's qword units
/// (sky2.c:1037-1075 `sky2_ramset`: input is KiB × 1024/8). RX
/// queues get the four thresholds, TX queues only store-and-forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamThresholds {
    /// `RB_RX_UTHP` = space − space/4 (high-priority, ¾ full)
    /// (sky2.c:1052-1053).
    pub upper_high: u32,
    /// `RB_RX_LTHP` = space/2 (sky2.c:1054).
    pub lower_high: u32,
    /// `RB_RX_UTPP` = space − 8192/8 (sky2.c:1057-1058).
    pub upper_pause: u32,
    /// `RB_RX_LTPP` = space/4 (sky2.c:1059).
    pub lower_pause: u32,
}

/// Compute the RX thresholds for `space` qwords.
///
/// `upper_pause` deliberately uses **wrapping** subtraction: sky2.c:1057
/// is plain `u32` C arithmetic (`space - 8192/8`), so a queue smaller
/// than 1024 qwords (128 KiB) wraps there too — the chip evidently
/// tolerates the wrapped value on Linux, and inventing a clamped one
/// would be inventing hardware behaviour. The test suite pins this.
pub const fn ram_thresholds(space: u32) -> RamThresholds {
    RamThresholds {
        upper_high: space - space / 4,
        lower_high: space / 2,
        upper_pause: space.wrapping_sub(8192 / 8),
        lower_pause: space / 4,
    }
}

/// Status-unit timer init values in chip clock ticks for a 125 MHz
/// Yukon-EC (`sky2_us2clk = mhz * us`, sky2.c:3085-3093 + 3415-3417):
/// TX index report every 1000 µs, ISR flush every 20 µs, level flush
/// every 100 µs.
pub const fn status_timer_inis() -> (u32, u32, u32) {
    (
        125 * 1000, // sky2_write32(STAT_TX_TIMER_INI, sky2_us2clk(hw, 1000))
        125 * 20,   // sky2_write32(STAT_ISR_TIMER_INI, sky2_us2clk(hw, 20))
        125 * 100,  // sky2_write32(STAT_LEV_TIMER_INI, sky2_us2clk(hw, 100))
    )
}

/// Inter-packet-gap field for `GM_SERIAL_MODE` at the given speed
/// (`sky2_set_ipg`, sky2.c:773-785: 0x1e above 100 Mbps, 0x18
/// otherwise; sky2.h:1817-1818).
pub const fn ipg_for_speed(speed_mbps: u16) -> u16 {
    if speed_mbps > 100 { 0x1e } else { 0x18 }
}

/// `GM_SERIAL_MODE` value used at init: data-blinder 4 + VLAN frame
/// support + IPG 0x1e (sky2.c:970-974; jumbo bit deliberately off —
/// MTU stays 1500).
pub const fn serial_mode() -> u16 {
    const DATA_BLIND_DEF: u16 = 0x04; // sky2.h:1816
    const GM_SMOD_VLAN_ENA: u16 = 1 << 9; // sky2.h:1805
    const GM_SMOD_DATABL_MSK: u16 = 0x1f << 11; // sky2.h:1803
    ((DATA_BLIND_DEF << 11) & GM_SMOD_DATABL_MSK) | GM_SMOD_VLAN_ENA | ipg_for_speed(1000)
}

/// `GM_TX_PARAM` value: jam length 3, jam IPG 0x0b, IPG-jam 0x1c,
/// backoff limit 4 (sky2.c:957-961, sky2.h:1784-1798 defaults).
pub const fn tx_param() -> u16 {
    const GM_TXPA_JAMLEN_MSK: u16 = 0x03 << 14; // sky2.h:1784
    const GM_TXPA_JAMIPG_MSK: u16 = 0x1f << 9; // sky2.h:1785
    const GM_TXPA_JAMDAT_MSK: u16 = 0x1f << 4; // sky2.h:1786
    const TX_JAM_LEN_DEF: u16 = 0x03; // sky2.h:1799
    const TX_JAM_IPG_DEF: u16 = 0x0b; // sky2.h:1800
    const TX_IPG_JAM_DEF: u16 = 0x1c; // sky2.h:1801
    const TX_BOF_LIM_DEF: u16 = 0x04; // sky2.h:1802
    ((TX_JAM_LEN_DEF << 14) & GM_TXPA_JAMLEN_MSK)
        | ((TX_JAM_IPG_DEF << 9) & GM_TXPA_JAMIPG_MSK)
        | ((TX_IPG_JAM_DEF << 4) & GM_TXPA_JAMDAT_MSK)
        | (TX_BOF_LIM_DEF & 0x0f)
}

/// `GM_RX_CTRL` value: pass unicast + multicast, strip the FCS
/// (sky2.c:948-949, sky2.h:1776-1778).
pub const fn rx_mac_ctrl() -> u16 {
    (1 << 15) | (1 << 14) | (1 << 13) // GM_RXCR_UCF_ENA | MCF_ENA | CRC_DIS
}

/// `GM_TX_CTRL` value: collision threshold 4 (`TX_COL_THR(TX_COL_DEF)`,
/// sky2.c:945, sky2.h:1771).
pub const fn tx_mac_ctrl() -> u16 {
    (4 << 10) & (7 << 10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    // --- List elements --------------------------------------------------

    #[test]
    fn le_is_exactly_eight_bytes() {
        assert_eq!(core::mem::size_of::<Le>(), 8);
        assert_eq!(core::mem::align_of::<Le>(), 4);
    }

    #[test]
    fn tx_packet_element_layout() {
        let le = Le::tx_packet(0xDEAD_BEEF, 1514);
        assert_eq!(le.addr.to_le_bytes(), [0xEF, 0xBE, 0xAD, 0xDE]);
        assert_eq!(le.length.to_le_bytes(), [0xEA, 0x05]);
        assert_eq!(le.ctrl, EOP);
        assert_eq!(le.opcode, OP_PACKET | HW_OWNER);
        assert!(le.hw_owned());
    }

    #[test]
    fn rx_buffer_element_has_no_ctrl_and_max_len() {
        let le = Le::rx_buffer(0x1000_0000, u16::MAX);
        assert_eq!(le.ctrl, 0);
        assert_eq!(le.opcode, OP_PACKET | HW_OWNER);
        assert_eq!(le.length, u16::MAX);
        assert_eq!(le.addr, 0x1000_0000);
    }

    #[test]
    fn addr64_element_layout() {
        let le = Le::addr64(0x0000_0001);
        assert_eq!(le.opcode, OP_ADDR64 | HW_OWNER);
        assert_eq!(le.length, 0);
        assert_eq!(le.ctrl, 0);
        assert_eq!(le.addr, 1);
    }

    #[test]
    fn le_hw_owned_tracks_the_owner_bit() {
        let mut le = Le::tx_packet(0, 64);
        assert!(le.hw_owned());
        le.opcode &= !HW_OWNER; // hardware clears it when done
        assert!(!le.hw_owned());
    }

    // --- Status parsing (adversarial) -----------------------------------

    fn status_bytes(opcode: u8, status: u32, length: u16, css: u8) -> Vec<u8> {
        let mut v: Vec<u8> = status.to_le_bytes().to_vec();
        v.extend_from_slice(&length.to_le_bytes());
        v.push(css);
        v.push(opcode);
        v
    }

    #[test]
    fn status_truncated_inputs_return_none() {
        let full = status_bytes(OP_RXSTAT | HW_OWNER, 0, 100, 0);
        for cut in 0..8 {
            assert_eq!(parse_status(&full[..cut]), None, "cut at {cut}");
        }
        assert_eq!(parse_status(&[]), None);
    }

    #[test]
    fn status_without_hw_owner_is_none() {
        let bytes = status_bytes(OP_RXSTAT, (100 << 16) | GMR_FS_RX_OK, 100, 0);
        assert_eq!(parse_status(&bytes), None);
    }

    #[test]
    fn status_rx_good_frame() {
        let len = 1500u16;
        let bytes = status_bytes(
            OP_RXSTAT | HW_OWNER,
            (u32::from(len) << 16) | GMR_FS_RX_OK,
            len,
            0,
        );
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::Rx { len: Some(1500) })
        );
    }

    #[test]
    fn status_rx_length_mismatch_drops() {
        // LE says 1500, the MAC's GMR_FS_LEN says 1499: sky2.c:2630
        // treats it as an error — no copy, buffer re-submitted.
        let bytes = status_bytes(OP_RXSTAT | HW_OWNER, (1499 << 16) | GMR_FS_RX_OK, 1500, 0);
        assert_eq!(parse_status(&bytes), Some(StatusEntry::Rx { len: None }));
    }

    #[test]
    fn status_rx_any_error_bit_drops() {
        let bytes = status_bytes(
            OP_RXSTAT | HW_OWNER,
            (100 << 16) | GMR_FS_RX_OK | 0x2, // GMR_FS_CRC_ERR
            100,
            0,
        );
        assert_eq!(parse_status(&bytes), Some(StatusEntry::Rx { len: None }));
    }

    #[test]
    fn status_rx_without_rx_ok_drops() {
        let bytes = status_bytes(OP_RXSTAT | HW_OWNER, 100 << 16, 100, 0);
        assert_eq!(parse_status(&bytes), Some(StatusEntry::Rx { len: None }));
    }

    #[test]
    fn status_rx_huge_length_passes_through() {
        // A bogus length is *not* rejected here — the kernel caps the
        // copy at its buffer size (defence lives where the copy is).
        let bytes = status_bytes(
            OP_RXSTAT | HW_OWNER,
            (0x7fff << 16) | GMR_FS_RX_OK,
            0x7fff,
            0,
        );
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::Rx { len: Some(0x7fff) })
        );
    }

    #[test]
    fn status_rx_vlan_flag_still_good() {
        let bytes = status_bytes(
            OP_RXSTAT | HW_OWNER,
            (64 << 16) | GMR_FS_RX_OK | (1 << 13), // GMR_FS_VLAN
            64,
            0,
        );
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::Rx { len: Some(64) })
        );
    }

    #[test]
    fn status_rx_for_port1_is_ignored() {
        let bytes = status_bytes(
            OP_RXSTAT | HW_OWNER,
            (64 << 16) | GMR_FS_RX_OK,
            64,
            CSS_LINK_BIT,
        );
        assert_eq!(parse_status(&bytes), Some(StatusEntry::Ignored));
    }

    #[test]
    fn status_tx_complete_masks_to_twelve_bits() {
        // sky2.c:2777: port 0 uses `status & 0xfff` regardless of the
        // css byte (the port1 field lives above bit 12).
        let bytes = status_bytes(OP_TXINDEXLE | HW_OWNER, 0xCDE0_0123, 0, CSS_LINK_BIT);
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::TxComplete { next: 0x123 })
        );
    }

    #[test]
    fn status_tx_complete_zero_and_wrap() {
        let bytes = status_bytes(OP_TXINDEXLE | HW_OWNER, 0, 0, 0);
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::TxComplete { next: 0 })
        );
        let bytes = status_bytes(OP_TXINDEXLE | HW_OWNER, 127, 0, 0);
        assert_eq!(
            parse_status(&bytes),
            Some(StatusEntry::TxComplete { next: 127 })
        );
    }

    #[test]
    fn status_unknown_opcodes_are_ignored_not_errors() {
        // RXCHKS / RXVLAN / RSS_HASH / garbage: consumed and skipped
        // (sky2.c:2715-2735 has explicit arms; we disable those
        // offloads entirely).
        for opcode in [0x62u8, 0x64, 0x65, 0x00, 0x11, 0xFF] {
            let bytes = status_bytes(opcode | HW_OWNER, 0, 0, 0);
            assert_eq!(
                parse_status(&bytes),
                Some(StatusEntry::Ignored),
                "opcode {opcode:#x}"
            );
        }
    }

    // --- SMI encoding ---------------------------------------------------

    #[test]
    fn smi_ctrl_read_matches_sky2_macro() {
        // gm_phy_read(PHY_MARV_PHY_STAT = 0x11): sky2.c:177-178.
        assert_eq!(smi_ctrl(0, 0x11, true), (0x11 << 6) | (1 << 5));
        // write has no OP_RD bit: sky2.c:154-155.
        assert_eq!(smi_ctrl(0, 0x11, false), 0x11 << 6);
    }

    #[test]
    fn smi_ctrl_masks_out_of_range_fields() {
        // sky2.h:1829-1830 macros mask (0x1f) — they never panic and
        // never bleed into the neighbouring field.
        let ctrl = smi_ctrl(33, 0x40, true);
        assert_eq!(ctrl & SMI_PHY_MSK, (1u16) << 11); // 33 & 0x1f == 1
        assert_eq!(ctrl & SMI_REG_MSK, 0); // 0x40 & 0x1f == 0
        assert_eq!(ctrl & SMI_OP_RD, SMI_OP_RD); // read flag preserved
        // A write command never sets the read opcode.
        assert_eq!(smi_ctrl(0, 0x11, false) & SMI_OP_RD, 0);
    }

    #[test]
    fn smi_poll_conditions() {
        assert!(smi_read_done(SMI_RD_VAL));
        assert!(!smi_read_done(SMI_BUSY));
        assert!(smi_busy(SMI_BUSY));
        assert!(!smi_busy(0));
        assert!(smi_dead(0xffff));
        assert!(!smi_dead(0x0460));
    }

    // --- PHY identification ---------------------------------------------

    #[test]
    fn marvell_phy_id0() {
        assert!(is_marvell_phy(PHY_ID0_MARVELL));
        assert!(!is_marvell_phy(0x0142)); // wrong OUI nibble
        assert!(!is_marvell_phy(0xffff)); // floating MMIO
        assert!(!is_marvell_phy(0x0000));
    }

    #[test]
    fn yukon_ec_phy_id1() {
        assert!(is_yukon_ec_phy(PHY_ID1_YUKON_EC));
        assert!(!is_yukon_ec_phy(0x0C91)); // Yukon-2 88E1112, sky2.h:1224
        assert!(!is_yukon_ec_phy(0xffff));
    }

    // --- MAC validation -------------------------------------------------

    #[test]
    fn mac_valid_is_the_measured_address() {
        // docs/hardware.md §1.1 — the real MacBook EEPROM MAC.
        let mac = [0x00, 0x19, 0xe3, 0x39, 0xf4, 0xa2];
        assert!(mac_is_sane(&mac));
        assert!(!locally_administered(&mac)); // globally assigned
    }

    #[test]
    fn mac_invalid_shapes_are_rejected() {
        assert!(!mac_is_sane(&[0; 6])); // all zero
        assert!(!mac_is_sane(&[0xFF; 6])); // broadcast
        assert!(!mac_is_sane(&[0x01, 0, 0, 0, 0, 0])); // I/G bit = multicast
        assert!(!mac_is_sane(&[0x03, 2, 3, 4, 5, 6])); // multicast + LAA
    }

    #[test]
    fn mac_locally_administered_bit() {
        assert!(locally_administered(&[0x02, 0, 0, 0, 0, 0]));
        assert!(!locally_administered(&[0x00, 0, 0, 0, 0, 0]));
        assert!(locally_administered(&[0x06, 0, 0, 0, 0, 0])); // I/G + LAA
    }

    // --- Link / flow control --------------------------------------------

    #[test]
    fn link_resolved_1000_full() {
        // Measured link: 1000 Mbps full duplex (docs/hardware.md §1.1).
        let phystat = PS_SPDUP_RES | PS_LINK_UP | (3 << 14) | PS_FULL_DUP;
        assert_eq!(
            resolve_link(phystat),
            Some(ResolvedLink {
                speed_mbps: 1000,
                full_duplex: true
            })
        );
    }

    #[test]
    fn link_resolved_100_half_and_10_full() {
        let p100h = PS_SPDUP_RES | PS_LINK_UP | (1 << 14);
        assert_eq!(
            resolve_link(p100h),
            Some(ResolvedLink {
                speed_mbps: 100,
                full_duplex: false
            })
        );
        let p10f = PS_SPDUP_RES | PS_LINK_UP | PS_FULL_DUP;
        assert_eq!(
            resolve_link(p10f),
            Some(ResolvedLink {
                speed_mbps: 10,
                full_duplex: true
            })
        );
    }

    #[test]
    fn link_down_or_unresolved_is_none() {
        assert_eq!(resolve_link(0), None);
        assert_eq!(resolve_link(PS_LINK_UP), None); // no SPDUP_RES
        assert_eq!(resolve_link(PS_SPDUP_RES), None); // link not up
        assert_eq!(resolve_link(!(PS_LINK_UP | PS_SPDUP_RES)), None);
    }

    #[test]
    fn flow_both_when_both_advertise_pause() {
        let advert = phy_advertisement(); // includes PC | ASP
        let lpa = AN_PAUSE_CAP; // partner: symmetric pause
        let link = ResolvedLink {
            speed_mbps: 1000,
            full_duplex: true,
        };
        assert_eq!(flow_control(advert, lpa, link), FlowControl::Both);
    }

    #[test]
    fn flow_rx_when_only_we_advertise_asym() {
        // advert has PC but partner doesn't → asymmetric receive
        // (sky2.c:2267-2269).
        let advert = AN_PAUSE_CAP | AN_PAUSE_ASYM;
        let lpa = 0;
        let link = ResolvedLink {
            speed_mbps: 1000,
            full_duplex: true,
        };
        assert_eq!(flow_control(advert, lpa, link), FlowControl::Rx);
    }

    #[test]
    fn flow_tx_when_partner_requires_both_bits() {
        let advert = AN_PAUSE_ASYM;
        let lpa = AN_PAUSE_CAP | AN_PAUSE_ASYM;
        let link = ResolvedLink {
            speed_mbps: 1000,
            full_duplex: true,
        };
        assert_eq!(flow_control(advert, lpa, link), FlowControl::Tx);
    }

    #[test]
    fn flow_none_on_half_duplex_below_gigabit() {
        // sky2.c:2274-2276 — the Yukon-EC rule.
        let advert = AN_PAUSE_CAP;
        let lpa = AN_PAUSE_CAP;
        let link = ResolvedLink {
            speed_mbps: 100,
            full_duplex: false,
        };
        assert_eq!(flow_control(advert, lpa, link), FlowControl::None);
        // …but full duplex at 100 Mbps keeps it.
        let fd = ResolvedLink {
            speed_mbps: 100,
            full_duplex: true,
        };
        assert_eq!(flow_control(advert, lpa, fd), FlowControl::Both);
    }

    #[test]
    fn flow_none_when_nobody_advertises() {
        let link = ResolvedLink {
            speed_mbps: 1000,
            full_duplex: true,
        };
        assert_eq!(flow_control(0, 0, link), FlowControl::None);
    }

    // --- Bring-up value composition --------------------------------------

    #[test]
    fn serial_mode_value() {
        // (4 << 11) | VLAN_ENA(1<<9) | 0x1e = 0x2000 | 0x200 | 0x1e.
        assert_eq!(serial_mode(), 0x221E);
    }

    #[test]
    fn tx_param_value() {
        // (3<<14) | (0x0b<<9) | (0x1c<<4) | 4 = 0xC000|0x1600|0x1C0|4.
        assert_eq!(tx_param(), 0xD7C4);
    }

    #[test]
    fn rx_and_tx_mac_ctrl_values() {
        assert_eq!(rx_mac_ctrl(), 0xE000); // UCF | MCF | CRC_DIS
        assert_eq!(tx_mac_ctrl(), 0x1000); // TX_COL_THR(4)
    }

    #[test]
    fn phy_advertisement_value() {
        // CSMA|100FD|100HD|10FD|10HD|PC|ASP = 0x0DE1.
        assert_eq!(phy_advertisement(), 0x0DE1);
        assert_eq!(phy_1000t_ctrl(), 0x0300); // AFD | AHD
        assert_eq!(phy_ctrl_autoneg(), 0x9200); // RESET | ANE | RE_CFG
    }

    #[test]
    fn phy_ext_ctrl_ec_composition() {
        // Full register: clear 0xF70 (downshift counters + MAC clock),
        // set MAC-S 25 MHz (0x70) + DSC_2(2)=0x400 + downshift-enable
        // (0x100) → 0xF5FF.
        assert_eq!(phy_ext_ctrl_ec(0xFFFF), 0xF5FF);
        // Already-programmed register is idempotent.
        let once = phy_ext_ctrl_ec(0x0000);
        assert_eq!(once, 0x0570);
        assert_eq!(phy_ext_ctrl_ec(once), once);
    }

    #[test]
    fn phy_specific_ctrl_gig_composition() {
        // Clear energy-detect (bits 9..8), set auto-crossover (bits
        // 6..5 = 0x60). 0xFF9F has the energy-detect bits set and the
        // crossover bits clear, so both halves of the composition are
        // visible in the result (0xFC9F | 0x60).
        assert_eq!(phy_specific_ctrl_gig(0xFF9F), 0xFCFF);
        assert_eq!(phy_specific_ctrl_gig(0), 0x0060);
        // On an all-ones register the crossover bits were already set.
        assert_eq!(phy_specific_ctrl_gig(0xFFFF), 0xFCFF);
    }

    #[test]
    fn rx_sizes_for_mtu_1500() {
        assert_eq!(rx_data_size(1500), 1520); // roundup(1518, 8)
        assert_eq!(rx_truncation_threshold(1500), Some(378)); // (1520-8)/4
    }

    #[test]
    fn rx_truncation_over_nine_bits_is_none() {
        // (roundup(mtu+18,8) - 8)/4 > 0x1FF ⇒ sky2.c:1555 takes the
        // RX_TRUNC_OFF path instead of programming a wrapped value.
        assert_eq!(rx_truncation_threshold(2052), None);
        // Boundary: 511 words is still representable.
        // size = 511*4+8 = 2052 → mtu = 2052-18 = 2034 → roundup(2052,8)
        // = 2056 → (2056-8)/4 = 512 > 511. Pick mtu where size=2048:
        // mtu+18 = 2048 → mtu = 2030 → (2048-8)/4 = 510 ≤ 511.
        assert_eq!(rx_truncation_threshold(2030), Some(510));
    }

    #[test]
    fn ram_buffer_partitions() {
        // 64 KiB: 8 + 2*(64-16)/3 = 8 + 32 = 40 (sky2.c:1681-1684).
        assert_eq!(
            ram_buffer_layout(64),
            Some(RamPartition {
                rx_space_kb: 40,
                tx_space_kb: 24
            })
        );
        // Small buffer (< 16 KiB): half.
        assert_eq!(
            ram_buffer_layout(8),
            Some(RamPartition {
                rx_space_kb: 4,
                tx_space_kb: 4
            })
        );
        // No RAM buffer at all (B2_E_0 == 0).
        assert_eq!(ram_buffer_layout(0), None);
    }

    #[test]
    fn ram_thresholds_match_sky2_ramset() {
        // 40 KiB = 5120 qwords.
        let t = ram_thresholds(5120);
        assert_eq!(t.upper_high, 5120 - 1280); // 3840
        assert_eq!(t.lower_high, 2560);
        assert_eq!(t.upper_pause, 5120 - 1024); // 4096
        assert_eq!(t.lower_pause, 1280);
    }

    #[test]
    fn ram_thresholds_small_queue_wraps_like_c() {
        // sky2.c:1057 is plain u32 subtraction; a queue under 1024
        // qwords wraps. Pinned here so nobody "fixes" it silently.
        let t = ram_thresholds(512);
        assert_eq!(t.upper_pause, 512u32.wrapping_sub(1024));
        assert_eq!(t.upper_pause, 0xFFFF_FE00); // −512, wrapped
        assert_eq!(t.upper_high, 384);
    }

    #[test]
    fn status_timers_for_125mhz_yukon_ec() {
        assert_eq!(status_timer_inis(), (125_000, 2_500, 12_500));
    }

    #[test]
    fn ipg_by_speed() {
        assert_eq!(ipg_for_speed(1000), 0x1e);
        assert_eq!(ipg_for_speed(100), 0x18);
        assert_eq!(ipg_for_speed(10), 0x18);
    }
}
