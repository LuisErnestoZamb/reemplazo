//! Marvell 88E8053 ("Yukon-2 EC") driver — the MacBook2,1's NIC, and
//! the reason this milestone exists: QEMU only models the Intel
//! e1000 (`AGENTS.md`, `docs/hardware.md` §1), so this driver is
//! written entirely against sources and can only be *proven* on the
//! real machine.
//!
//! ## Sources — no register here is remembered
//!
//! - Linux v6.6 `drivers/net/ethernet/marvell/sky2.c` / `sky2.h`
//!   (pinned raw URLs, SHA-256 `3fe71637…b4fbfb51` /
//!   `5a4e48ab…feb49a14b` — see `sky2-wire`'s module docs). Register
//!   offsets and init-sequence comments cite `sky2.c:NNNN` /
//!   `sky2.h:NNNN` line numbers of exactly those files.
//! - Measured over SSH from the running Debian install on the target
//!   (2026-11-21): PCI `11ab:4362` rev 22 = *Yukon-2 EC chip revision
//!   2*; BAR0 = MMIO 16 KiB at a 64-bit non-prefetchable address
//!   (`0xd0200000`); BAR2 = I/O 256 B (`0x1000`); IRQ 26 (pin A) with
//!   MSI available; EEPROM MAC `00:19:e3:39:f4:a2`; link 1000 Mbps
//!   full duplex, flow control; interface `enp1s0`.
//! - The pure logic (descriptor/status layouts, SMI encoding, PHY/MAC
//!   validation, register-value composition) lives in the host-tested
//!   `sky2-wire` crate; this module is only the MMIO/DMA glue.
//!
//! ## Design decisions (this milestone)
//!
//! - **Silent when absent** (`ata::probe` pattern): `init` returns
//!   `None` before printing anything when no `11ab:4362` exists, so
//!   QEMU — which has no sky2 model — sees a byte-identical boot and
//!   the 20-marker smoke chain stays green.
//! - **Polled, no interrupts, no MSI.** `B0_IMSK` is left at 0
//!   (explicitly written, sky2.c:2123 — the `sky2_close` value) and
//!   no PIC line is unmasked. Completions come from the **status
//!   ring**, which sky2_reset enables unconditionally with its three
//!   flush timers (sky2.c:3390-3421) — the hardware writes status
//!   elements regardless of the interrupt mask. That assumption is
//!   the one marked **[unverified]** in `docs/hardware.md` §1.9 and
//!   is exactly what the physical boot must confirm first. Interrupts
//!   (INTx, the 8259 line from config `0x3c`) are a later milestone.
//! - **Synchronous TX** (the e1000 `TX_POLLS` discipline): `transmit`
//!   does not return until the status ring reports the frame done,
//!   bounded by [`TX_POLLS`]. That buys two things: a wedged chip
//!   fails loudly on the *first* frame instead of after a full ring,
//!   and **one** TX buffer is enough — the buffer can only be
//!   rewritten after the DMA read completed. Making TX asynchronous
//!   later requires one buffer per ring slot.
//! - **DMA**: descriptor rings and packet buffers come from the frame
//!   allocator as *physical* addresses (`memory::alloc` →
//!   `Frame::start_phys`), identity-mapped by `entry.S` (first 4 GiB)
//!   so physical == virtual — the same contract `e1000.rs` relies on
//!   and the allocator guarantees (`memory.rs` tracks exactly that
//!   4 GiB). BAR0 must land below 4 GiB or we fail closed.
//! - **RX bookkeeping**: the chip assigns frames to RX buffers in
//!   submission order, so the *n*-th status entry belongs to the
//!   *n*-th buffer (mod [`RX_BUFFERS`]). Every RX status re-submits
//!   its buffer immediately — whether the frame is copied out, parked
//!   in the one-deep scratch slot, or dropped — which keeps the
//!   submission order equal to the status order. The scratch slot
//!   exists so frames arriving **while a transmit is waiting for its
//!   completion** are not lost behind it in the status FIFO; if a
//!   second frame completes during the same wait it is dropped (the
//!   alternative — an unbounded stash — risks blocking TX completion
//!   entries behind RX entries). Normal boot traffic never fills the
//!   slot; the drop is deliberate and documented, not silent
//!   corruption.
//! - **No RX/TX checksum offload, no VLAN offload, no TSO, no RSS**
//!   (sky2.c's `rx_set_checksum`/`BMU_ENA_RX_CHKSUM` are never
//!   written; the stack computes checksums) — `docs/hardware.md`
//!   §1.11-7/8/9. PHY LED programming (sky2.c:474-623) is skipped as
//!   cosmetic; the **link LED** is written at link-up (sky2.c:2196)
//!   because it is the one piece of hardware feedback a physical
//!   test can see without a serial console.
//! - **MAC from `B2_MAC_1`**, exactly like Linux (sky2.c:4665): the
//!   chip's EEPROM loader programs that register at power-on. There
//!   is no EEPROM controller in sky2.c (ethtool's `e` reads PCI VPD,
//!   sky2.c:4271) — hence no EEPROM checksum exists to write; the
//!   validation that *does* exist ([`wire::mac_is_sane`], applied by
//!   sky2.c:4671) runs here. An invalid MAC **fails closed** instead
//!   of Linux's random-address fallback: no CSPRNG has run yet at
//!   probe time and a silent random address would be untraceable on
//!   the wire.
//!
//! ## `SKY2_OK` and the on-hardware test
//!
//! `SKY2_OK` is printed **only** when a real sky2 was probed and
//! brought up (i.e. on the MacBook — QEMU can never produce it), so
//! it is deliberately **not** in xtask's marker chain, AGENTS.md or
//! README: there is no way to assert it in CI, and adding an
//! unassertable marker would only weaken the smoke's meaning.
//!
//! The physical validation (later step, ISO burned to DVD):
//!
//! 1. `cargo xtask check && cargo xtask build`, burn the ISO, boot
//!    the MacBook2,1 holding **C** at the chime (Option/C DVD boot).
//! 2. Expected serial/VGA lines, in order, after the `pci:` scan
//!    lines:
//!
//!    ```text
//!    sky2: found at 01:00.0
//!    sky2: mmio 0xd0200000, io 0x1000 (BAR2 unused — Linux never touches it)
//!    sky2: Yukon-2 EC chip revision 2 (1 port, ram buffer NNNK)
//!    sky2: MAC 00:19:e3:39:f4:a2
//!    sky2: PHY id 0x0141/0x0cc2
//!    sky2: link up, 1000 Mbps, full duplex, flow control both
//!    sky2: rings up — 128 TX + 512 RX LEs, 32 RX buffers, 512 status
//!    SKY2_OK
//!    ```
//!
//!    (Values above are the measured/expected ones; everything is
//!    printed as numeric fields read from the hardware.)
//! 3. `SKY2_OK` is followed by the **slirp-specific** chain
//!    (`NET_OK` pings `10.0.2.2`, DHCP asserts QEMU's lease) which
//!    can only fail closed on a real network — `FATAL: net: timeout
//!    …` about ten seconds later is the *expected* end of boot for
//!    this milestone. The follow-up milestone reorders boot for real
//!    networks (DHCP first, then sshd for remote validation).
//! 4. A failure *before* `SKY2_OK` prints `FATAL: sky2: …` with the
//!    register/step that misbehaved (every poll here is bounded, so
//!    the failure is a message, never a hang).

use crate::pci::{Scan, read32, write32};
use core::ptr::{read_volatile, write_bytes, write_volatile};
use core::sync::atomic::{Ordering, fence};
use pci::{CMD_BUS_MASTER, CMD_MEMORY_SPACE, MARVELL_VENDOR, SKY2_88E8053, mem_bar_address};
use sky2_wire as wire;
use sky2_wire::Le;

// ---------------------------------------------------------------------------
// Ring geometry
// ---------------------------------------------------------------------------

/// TX list elements: Linux's `roundup_ring_size(TX_DEF_PENDING=63)` =
/// `max(128, …)` (sky2.c:4144-4147). Power of two (sky2.c:74
/// `RING_NEXT`).
const TX_RING: u16 = 128;
/// RX list elements. Linux uses 1024 (sky2.c:34 `RX_LE_SIZE`); 512
/// still leaves 8× headroom over the 64 elements (2 per buffer × 32
/// buffers) that can ever be outstanding, and fits one 4 KiB frame —
/// the frame allocator hands out whole frames only.
const RX_LE_RING: u16 = 512;
/// RX packet buffers (Linux's `RX_MAX_PENDING` is 168 — sky2.c:35 —
/// we drain on every poll, so 32 buffers × 1520 B ≈ 48 KiB in flight
/// is ample and keeps the DMA footprint small).
const RX_BUFFERS: u16 = 32;
/// Status-ring entries (Linux sizes it for far larger rings:
/// `ports * roundup_pow2(3*RX_MAX_PENDING + TX_MAX_PENDING)` =
/// 2048 — sky2.c:4907). 512 = 16× our RX buffers; every drain cycle
/// consumes at most one entry per buffer plus TX reports.
const STATUS_SIZE: u16 = 512;

/// Ethernet MTU — jumbo is deliberately off (`docs/hardware.md`
/// §1.11-10); sky2.c:4656-4661 allows up to 9000, we never ask for it.
const MTU: u16 = 1500;
/// RX buffer capacity programmed into every RX element:
/// `roundup(1500 + 14 + 4, 8)` (sky2.c:1140-1147).
const RX_DATA_SIZE: u16 = wire::rx_data_size(MTU);
/// Bytes in one frame-allocator frame — also the TX buffer size and
/// the upper bound on any copy (RX frames are capped at
/// [`RX_DATA_SIZE`], what the chip may DMA into a buffer).
const BUF_BYTES: usize = 4096;

/// Spin budget for one transmit waiting on its status entry — the
/// same bound as `e1000::TX_POLLS`. Real silicon flushes the status
/// FIFO within one 100 µs level-timer period (sky2.c:3417), so the
/// success path needs a tiny fraction of this; the bound only turns
/// a wedged chip into `FATAL: sky2: …` instead of a hang.
const TX_POLLS: u32 = 10_000_000;
/// SMI (MDIO) poll budget. Linux allows `PHY_RETRIES = 1000` ×
/// `udelay(10 µs)` = 10 ms per access (sky2.c:40, 157-171); this spin
/// budget is the same order of magnitude (an MMIO read is ~µs).
const PHY_POLLS: u32 = 100_000;
/// Link-auto-negotiation deadline in milliseconds: gigabit AN takes
/// ~1-3 s; 10 s matches the stack's `OP_DEADLINE_MS` scale.
const LINK_DEADLINE_MS: u64 = 10_000;

// ---------------------------------------------------------------------------
// Register offsets — every one cited (sky2.h line numbers of the
// pinned v6.6 file; port-0 values of the SK_REG/Q_ADDR/Y2_QADDR/
// RB_ADDR/SK_GMAC_REG macros, sky2.h:665/739/767/823/2346)
// ---------------------------------------------------------------------------

// CSR bank (sky2.h:254-306 `enum csr_regs`).
const B0_CTST: u32 = 0x0004;
const B0_POWER_CTRL: u32 = 0x0007;
const B0_IMSK: u32 = 0x000c;
const B0_HWE_ISRC: u32 = 0x0010;
const B0_HWE_IMSK: u32 = 0x0014;
const B2_MAC_1: u32 = 0x0100; // + port*8, 6 bytes (sky2.h:272)
const B2_PMD_TYP: u32 = 0x0119;
const B2_MAC_CFG: u32 = 0x011a;
const B2_CHIP_ID: u32 = 0x011b;
const B2_E_0: u32 = 0x011c; // internal RAM, 4 KiB blocks (sky2.c:3222)
const B2_Y2_CLK_GATE: u32 = 0x011d;
const B2_Y2_HW_RES: u32 = 0x011e;
const B2_Y2_CLK_CTRL: u32 = 0x0120;
const B2_TI_CTRL: u32 = 0x0138;
const B2_TST_CTRL1: u32 = 0x0158;
const B2_I2C_IRQ: u32 = 0x0168;
// RAM interface (sky2.h:314-327, RAM_BUFFER(port, reg) = reg for port 0).
const B3_RI_WTO_BASE: u32 = 0x0190; // 12 timeout regs 0x0190..=0x019b (sky2.c:3373-3383)
const B3_RI_CTRL: u32 = 0x01a0;
// Descriptor-poll / timestamp / ASF timers (sky2.h:998-1016).
const B28_DPT_CTRL: u32 = 0x0e08;
const GMAC_TI_ST_CTRL: u32 = 0x0e18;
const B28_Y2_ASF_STAT_CMD: u32 = 0x0e68;
// Status unit (sky2.h:1053-1063).
const STAT_CTRL: u32 = 0x0e80;
const STAT_LAST_IDX: u32 = 0x0e84;
const STAT_LIST_ADDR_LO: u32 = 0x0e88;
const STAT_LIST_ADDR_HI: u32 = 0x0e8c;
const STAT_TX_IDX_TH: u32 = 0x0e98;
const STAT_FIFO_WM: u32 = 0x0eac;
const STAT_FIFO_ISR_WM: u32 = 0x0ead;
const STAT_LEV_TIMER_INI: u32 = 0x0eb0;
const STAT_LEV_TIMER_CTRL: u32 = 0x0eb8;
const STAT_TX_TIMER_INI: u32 = 0x0ec0;
const STAT_TX_TIMER_CTRL: u32 = 0x0ec8;
const STAT_ISR_TIMER_INI: u32 = 0x0ed0;
const STAT_ISR_TIMER_CTRL: u32 = 0x0ed8;
// PCI-config window through BAR0 (sky2.h:304-305).
const Y2_CFG_SPC: u32 = 0x1c00;
const Y2_CFG_AER: u32 = 0x1d00;
// Offsets inside the windowed PCI config space: PCI_STATUS (pci_regs.h:53),
// PCI_DEV_REG1/3 (sky2.h:12-15), PCI_ERR_UNCOR_STATUS (pci_regs.h:749).
const PCI_STATUS_OFF: u32 = 0x06;
const PCI_DEV_REG1: u32 = 0x40;
const PCI_DEV_REG3: u32 = 0x80;
const PCI_ERR_UNCOR_STATUS: u32 = 0x04;

// Port-0 "SK_REG(0, …)" registers (sky2.h:665, ports 0: +0, 1: +0x80).
const SK_TXA_CTRL: u32 = 0x0210; // TX arbiter (sky2.h:678)
const SK_LNK_LED_REG: u32 = 0x0c3c; // link LED (sky2.h:1048)
const SK_RX_GMF_CTRL_T: u32 = 0x0c48; // (sky2.h:1032)
const SK_RX_GMF_FL_MSK: u32 = 0x0c4c;
const SK_RX_GMF_FL_THR: u32 = 0x0c50;
const SK_RX_GMF_TR_THR: u32 = 0x0c54; // truncation threshold (sky2.h:1036)
const SK_RX_GMF_UP_THR: u32 = 0x0c58;
const SK_RX_GMF_LP_THR: u32 = 0x0c5a;
const SK_TX_GMF_CTRL_T: u32 = 0x0d48; // (sky2.h:1048 area, TX GMAC FIFO)
const SK_GMAC_CTRL: u32 = 0x0f00; // (sky2.h:1059)
const SK_GPHY_CTRL: u32 = 0x0f04;
const SK_GMAC_IRQ_SRC: u32 = 0x0f08;
const SK_GMAC_IRQ_MSK: u32 = 0x0f0c;
const SK_GMAC_LINK_CTRL: u32 = 0x0f10;

// Queue registers: Q_ADDR(q, offs) = 0x0400 + q + offs (sky2.h:739).
const B8_Q_REGS: u32 = 0x0400;
const Q_CSR: u32 = 0x34;
const Q_WM: u32 = 0x40;
// Queue base addresses (sky2.h:805-810).
const Q_R1: u16 = 0x0000; // RX queue 1
const Q_XS1: u16 = 0x0200; // sync TX queue 1 (unused — reset only)
const Q_XA1: u16 = 0x0280; // async TX queue 1 (sky2.c:110 `txqaddr[]`)
// Prefetch unit: Y2_QADDR(q, reg) = 0x0450 + q + reg (sky2.h:767).
const Y2_B8_PREF_REGS: u32 = 0x0450;
const PREF_UNIT_CTRL: u32 = 0x00;
const PREF_UNIT_LAST_IDX: u32 = 0x04;
const PREF_UNIT_ADDR_LO: u32 = 0x08;
const PREF_UNIT_ADDR_HI: u32 = 0x0c;
const PREF_UNIT_PUT_IDX: u32 = 0x14;
// RAM buffer: RB_ADDR(q, offs) = 0x0800 + q + offs (sky2.h:823).
const B16_RAM_REGS: u32 = 0x0800;
const RB_START: u32 = 0x00;
const RB_END: u32 = 0x04;
const RB_WP: u32 = 0x08;
const RB_RP: u32 = 0x0c;
const RB_RX_UTPP: u32 = 0x10;
const RB_RX_LTPP: u32 = 0x14;
const RB_RX_UTHP: u32 = 0x18;
const RB_RX_LTHP: u32 = 0x1c;
const RB_CTRL: u32 = 0x28;
// GMAC registers: SK_GMAC_REG(port, reg) = 0x2800 + port*0x1000 + reg
// (sky2.h:2346); GM_* are the raw offsets from sky2.h:1631-1669.
const BASE_GMAC_1: u32 = 0x2800;
const GM_GP_CTRL: u32 = 0x0004;
const GM_TX_CTRL: u32 = 0x0008;
const GM_RX_CTRL: u32 = 0x000c;
const GM_TX_FLOW_CTRL: u32 = 0x0010;
const GM_TX_PARAM: u32 = 0x0014;
const GM_SERIAL_MODE: u32 = 0x0018;
const GM_SRC_ADDR_1L: u32 = 0x001c;
const GM_SRC_ADDR_2L: u32 = 0x0028;
const GM_MC_ADDR_H1: u32 = 0x0034; // ..= H4 at 0x0040, step 4
const GM_TX_IRQ_MSK: u32 = 0x0050;
const GM_RX_IRQ_MSK: u32 = 0x0054;
const GM_TR_IRQ_MSK: u32 = 0x0058;
const GM_SMI_CTRL: u32 = 0x0080;
const GM_SMI_DATA: u32 = 0x0084;
const GM_PHY_ADDR: u32 = 0x0088;
const GM_MIB_CNT_BASE: u32 = 0x0100;
const GM_MIB_CNT_END: u32 = 0x025C;

// ---------------------------------------------------------------------------
// Register values (bits) — all cited; the composed *values* come from
// sky2-wire, this module only carries the raw bit definitions.
// ---------------------------------------------------------------------------

// B0_CTST (sky2.h:366-384).
const CS_RST_SET: u8 = 1;
const CS_RST_CLR: u8 = 1 << 1;
const CS_MRST_CLR: u8 = 1 << 3;
const Y2_LED_STAT_ON: u16 = 1 << 9;
const Y2_ASF_DISABLE: u16 = 1 << 12;
// B28_Y2_ASF_STAT_CMD (sky2.h:1956).
const Y2_ASF_RESET: u8 = 1 << 3;
// B0_POWER_CTRL (sky2.h:391-398): the VAUX→VCC switch sky2_power_on
// performs (sky2.c:199-201).
const PC_POWER_VCC: u8 = (1 << 7) | (1 << 5) | (1 << 2) | (1 << 1); // VAUX_ENA|VCC_ENA|VAUX_OFF|VCC_ON
// B2_Y2_CLK_CTRL (sky2.h:621).
const Y2_CLK_DIV_DIS: u32 = 1;
// B2_TST_CTRL1 (sky2.h:510-511): PCI-config window write enable.
const TST_CFG_WRITE_ON: u8 = 1 << 1;
const TST_CFG_WRITE_OFF: u8 = 1 << 0;
// B2_MAC_CFG chip-revision field (sky2.h:531).
const CFG_CHIP_R_MSK: u8 = 0xf << 4;
// B2_Y2_HW_RES: CFG_DUAL_MAC_MSK = LINK_2|LINK_1 (sky2.h:605-609).
const CFG_DUAL_MAC_MSK: u8 = 0x03;
// B2_Y2_CLK_GATE (sky2.h:592).
const Y2_STATUS_LNK2_INAC: u8 = 1 << 7;
// B2_CHIP_ID (sky2.h:540) + Yukon-EC revisions (sky2.h:553-556).
const CHIP_ID_YUKON_EC: u8 = 0xb6;
const CHIP_REV_YU_EC_A1: u8 = 0;
// PCI window: PCI_Y2_PHY1_POWD (sky2.h:38), PCI_STATUS_ERROR_BITS
// (linux/pci.h:46-51 = DETECTED_PARITY|SIG_SYSTEM_ERROR|REC_MASTER_
// ABORT|REC_TARGET_ABORT|SIG_TARGET_ABORT|PARITY = 0xF900).
const PCI_Y2_PHY1_POWD: u32 = 1 << 26;
const PCI_STATUS_ERROR_BITS: u16 = 0xF900;
// Hardware-error mask (sky2.h:466, 474-481): Y2_HWE_ALL_MASK | Y2_IS_PCI_EXP.
const Y2_IS_PCI_EXP: u32 = 1 << 25;
const Y2_HWE_ALL_MASK: u32 = (1 << 29) | (1 << 27) | (1 << 26) | 0x3F00 | 0x3F;
// Timers (sky2.h:627-629, 1949-1950, DPT sky2.h ~513).
const TIM_STOP: u8 = 1 << 1;
const TIM_CLR_IRQ: u8 = 1 << 0;
const TIM_START: u8 = 1 << 2;
const DPT_STOP: u32 = 1 << 0;
const GMT_ST_STOP: u8 = 1 << 1;
const GMT_ST_CLR_IRQ: u8 = 1 << 0;
// TX arbiter (sky2.h:678).
const TXA_ENA_ARB: u8 = 1 << 1;
// RAM interface (sky2.h:644-656): RI_RST_CLR + SK_RI_TO_53 = 36.
const RI_RST_CLR: u8 = 1 << 1;
const SK_RI_TO_53: u8 = 36;
// Status unit (sky2.h:2006-2010).
const SC_STAT_RST_SET: u32 = 1 << 0;
const SC_STAT_RST_CLR: u32 = 1 << 1;
const SC_STAT_OP_ON: u32 = 1 << 3;
const SC_STAT_CLR_IRQ: u32 = 1 << 4;
// GPHY/GMAC/link control (sky2.h:2028-2059).
const GMC_PAUSE_ON: u8 = 1 << 3;
const GMC_PAUSE_OFF: u8 = 1 << 2;
const GMC_RST_CLR: u8 = 1 << 1;
const GPC_RST_SET: u8 = 1 << 0;
const GPC_RST_CLR: u8 = 1 << 1;
const GMLC_RST_SET: u8 = 1 << 0;
const GMLC_RST_CLR: u8 = 1 << 1;
// GM_GP_CTRL enable bits (sky2.h:1746-1747).
const GM_GPCR_TX_ENA: u16 = 1 << 12;
const GM_GPCR_RX_ENA: u16 = 1 << 11;
// GMAC IRQ mask default (sky2.h:2071-2073: GM_IS_TX_FF_UR|GM_IS_RX_FF_OR).
const GMAC_DEF_MSK: u8 = (1 << 3) | (1 << 1);
// GM_RX_CTRL bits (sky2.h:1776-1778) — value composed in sky2-wire.
const GM_RXCR_UCF_ENA: u16 = 1 << 15;
const GM_RXCR_MCF_ENA: u16 = 1 << 14;
// GM_PHY_ADDR MIB-clear (sky2.h:1834).
const GM_PAR_MIB_CLR: u16 = 1 << 5;
// GMAC FIFO control (sky2.h:1876-1904).
const RX_TRUNC_ON: u32 = 1 << 27;
const RX_TRUNC_OFF: u32 = 1 << 26;
const GMF_RST_CLR: u8 = 1 << 1;
const GMF_OPER_ON: u32 = 1 << 3;
const GMF_RX_F_FL_ON: u32 = 1 << 7;
const RX_GMF_FL_THR_DEF: u16 = 0xa; // sky2.h:1902 (+1 workaround, sky2.c:1000)
const TX_STFW_ENA: u32 = 1 << 30; // sky2.h:1929
// BMU control (sky2.h:877-892).
const BMU_CLR_RESET: u32 = 0x10 | 0x04 | 0x02; // FIFO_RST|OP_OFF|RST_CLR
const BMU_OPER_INIT: u32 = 0x800 | 0x400 | 0x100 | 0x20 | 0x08; // CLR_IRQ_PAR|CLR_IRQ_CHK|START|FIFO_ENA|OP_ON
const BMU_FIFO_OP_ON: u32 = 0x80;
const BMU_WM_DEFAULT: u32 = 0x600;
const BMU_WM_PEX: u32 = 0x80; // sky2.c:1528 (PCIe watermark)
// Prefetch unit control (sky2.h:928-931).
const PREF_UNIT_RST_SET: u32 = 1 << 0;
const PREF_UNIT_RST_CLR: u32 = 1 << 1;
const PREF_UNIT_OP_ON: u32 = 1 << 3;
// RAM buffer control (sky2.h:963-971).
const RB_RST_CLR: u8 = 1 << 1;
const RB_RST_SET: u8 = 1 << 0;
const RB_ENA_STFWD: u8 = 1 << 5;
const RB_ENA_OP_MD: u8 = 1 << 3;
// Link LED (sky2.h:1091-1094), written by sky2_link_up (sky2.c:2196-2197).
const LINK_LED_ON: u8 = 0x02 | 0x10 | 0x04; // LINKLED_ON|BLINK_OFF|LINKSYNC_OFF
// PHY registers (sky2.h:1134-1155).
const PHY_MARV_CTRL: u8 = 0x00;
const PHY_MARV_ID0: u8 = 0x02;
const PHY_MARV_ID1: u8 = 0x03;
const PHY_MARV_AUNE_ADV: u8 = 0x04;
const PHY_MARV_AUNE_LP: u8 = 0x05;
const PHY_MARV_1000T_CTRL: u8 = 0x09;
const PHY_MARV_PHY_CTRL: u8 = 0x10;
const PHY_MARV_PHY_STAT: u8 = 0x11;
const PHY_MARV_INT_MASK: u8 = 0x12;
const PHY_MARV_EXT_CTRL: u8 = 0x14;
/// `PHY_M_IS_AN_COMPL` — sky2.c:679 writes it into the PHY mask at
/// the end of `sky2_phy_init` (sky2.h:1390). We never take the PHY
/// interrupt (polled), but the mask controls what latches in
/// `PHY_MARV_INT_STAT`, and the future IRQ milestone wants this state.
const PHY_M_IS_AN_COMPL: u16 = 1 << 11;
/// `PHY_M_DEF_MSK` (LSP|LST|DUP change, sky2.h:1405-1407) — written
/// by `sky2_link_up` (sky2.c:2191).
const PHY_M_DEF_MSK: u16 = (1 << 14) | (1 << 10) | (1 << 13);
/// Remote-fault bit in `PHY_MARV_AUNE_LP` (sky2.h:1240 `PHY_M_AN_RF`)
/// — checked by `sky2_autoneg_done` (sky2.c:2253-2256).
const PHY_M_AN_RF: u16 = 1 << 13;
/// SMI PHY address: `PHY_ADDR_MARV = 0` (sky2.h:815).
const PHY_ADDR_MARV: u8 = 0;

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: sky2: {msg}");
    crate::halt()
}

/// Unwrap an SMI result on the boot-critical path: a dead or timed
/// out SMI bus with a device present fails closed (`FATAL: sky2: …`).
fn or_fatal<T>(result: Result<T, &'static str>) -> T {
    match result {
        Ok(value) => value,
        Err(msg) => fatal(msg),
    }
}

/// Hand out one physical frame as DMA memory; identity map makes
/// phys == virt (same contract as `e1000::alloc_frame`).
fn alloc_frame(msg: &'static str) -> *mut u8 {
    match crate::memory::alloc() {
        Some(frame) => frame.start_phys() as *mut u8,
        None => fatal(msg),
    }
}

// ---------------------------------------------------------------------------
// MMIO accessors — the `unsafe` budget of this driver lives here.
// ---------------------------------------------------------------------------

/// Every register offset used below is < 0x4000, the measured BAR0
/// size (docs/hardware.md §1.2), and `init` refuses any BAR0 ≥ 4 GiB
/// (outside `entry.S`'s identity map).
fn mmio_read8(base: u64, reg: u32) -> u8 {
    // SAFETY: `base` is the validated BAR0, `reg` is a byte-wide,
    // 1-byte-aligned register offset inside the 16 KiB window, and
    // the access is a volatile device read.
    unsafe { read_volatile((base + u64::from(reg)) as *const u8) }
}

fn mmio_read16(base: u64, reg: u32) -> u16 {
    // SAFETY: as `mmio_read8`, plus `reg` is 2-byte aligned (every
    // 16-bit offset used is even) and the width matches the chip's.
    unsafe { read_volatile((base + u64::from(reg)) as *const u16) }
}

fn mmio_read32(base: u64, reg: u32) -> u32 {
    // SAFETY: as `mmio_read8`, plus `reg` is 4-byte aligned.
    unsafe { read_volatile((base + u64::from(reg)) as *const u32) }
}

fn mmio_write8(base: u64, reg: u32, val: u8) {
    // SAFETY: as `mmio_read8` (write).
    unsafe { write_volatile((base + u64::from(reg)) as *mut u8, val) }
}

fn mmio_write16(base: u64, reg: u32, val: u16) {
    // SAFETY: as `mmio_read16` (write).
    unsafe { write_volatile((base + u64::from(reg)) as *mut u16, val) }
}

fn mmio_write32(base: u64, reg: u32, val: u32) {
    // SAFETY: as `mmio_read32` (write).
    unsafe { write_volatile((base + u64::from(reg)) as *mut u32, val) }
}

const fn q_addr(queue: u16, offs: u32) -> u32 {
    B8_Q_REGS + queue as u32 + offs // Q_ADDR, sky2.h:739
}

const fn y2_qaddr(queue: u16, offs: u32) -> u32 {
    Y2_B8_PREF_REGS + queue as u32 + offs // Y2_QADDR, sky2.h:767
}

const fn rb_addr(queue: u16, offs: u32) -> u32 {
    B16_RAM_REGS + queue as u32 + offs // RB_ADDR, sky2.h:823
}

const fn gma(reg: u32) -> u32 {
    BASE_GMAC_1 + reg // SK_GMAC_REG(0, reg), sky2.h:2346
}

/// `RING_NEXT` from sky2.c:74: `((x)+1) & ((s)-1)`; `size` is always
/// a power of two here (all four rings).
const fn next_index(idx: u16, size: u16) -> u16 {
    (idx + 1) & (size - 1)
}

/// The same rule for the 8-bit RX *buffer* index (mod [`RX_BUFFERS`],
/// also a power of two).
const fn next_buffer(idx: u8) -> u8 {
    (idx + 1) & (RX_BUFFERS as u8 - 1)
}

/// A probed, enabled 88E8053 with live status/TX/RX rings.
///
/// The struct owns raw pointers into DMA memory shared with the
/// device; access goes through volatile reads/writes only (never
/// Rust references to hardware-owned memory). Boot code is
/// single-threaded, like `E1000`.
pub struct Sky2 {
    mmio: u64,
    mac: [u8; 6],
    /// TX list-element ring (one frame).
    tx_le: *mut Le,
    /// The single synchronous-TX buffer (see module docs: safe
    /// because `transmit` does not return until the chip reports the
    /// frame done).
    tx_buf: *mut u8,
    /// Next TX ring slot to fill / first slot not yet reported done
    /// (the `tx_prod`/`tx_cons` pair of sky2.h:2225-2226).
    tx_prod: u16,
    tx_cons: u16,
    /// Upper 32 bits of the last TX buffer address (sky2.c:1849-1856:
    /// an `OP_ADDR64` element is emitted only on a change; always 0
    /// with our identity-mapped frames, but the latch must be
    /// initialized — see `tx_init`).
    tx_last_upper: u32,
    /// RX list-element ring (one frame).
    rx_le: *mut Le,
    /// RX packet buffers (one frame each, 8-byte aligned by the
    /// allocator — the FIFO-hang workaround of sky2.c:1457-1464).
    rx_bufs: [*mut u8; RX_BUFFERS as usize],
    /// Scratch frame for one RX that completed during a transmit
    /// wait (module docs).
    rx_saved: *mut u8,
    /// 0 = scratch empty, else the saved frame's length (capped at
    /// `RX_DATA_SIZE`).
    rx_saved_len: usize,
    /// Next RX ring slot to submit (LE index, mod `RX_LE_RING`).
    rx_put: u16,
    /// Buffer index for the next RX status entry (mod `RX_BUFFERS`;
    /// the n-th status belongs to the n-th submitted buffer).
    rx_status_next: u8,
    /// Frames dropped because the scratch slot was already occupied
    /// during a transmit wait — reported by the shell's `netinfo`.
    rx_dropped: u32,
    /// `B2_E_0 != 0`: the chip has an internal RAM buffer to
    /// partition (sky2.c:3222, 1673-1694).
    ram_buffer: bool,
    /// Status ring (one frame), written by the chip's status BMU.
    st_le: *mut u8,
    /// Next status slot to consume (mod `STATUS_SIZE`).
    st_idx: u16,
}

/// Link state for observability (`netinfo`): `Unknown` when the
/// driver does not track it (e1000) or the PHY cannot be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    Unknown,
    Down,
    Up { speed_mbps: u16, full_duplex: bool },
}

/// Probe, enable, identify, reset, bring the rings and PHY up, wait
/// for link, verify with `SKY2_OK`. Returns `None` **without any
/// output** when no `11ab:4362` exists (QEMU — the smoke's marker
/// chain must not move); parks on a present-but-broken device.
pub fn init(scan: &Scan) -> Option<Sky2> {
    let dev = scan.find(MARVELL_VENDOR, SKY2_88E8053)?;
    serial_println!("sky2: found at {}", dev.location);
    let loc = dev.location;

    // --- BARs and command register --------------------------------------
    // BAR0 is 64-bit non-prefetchable (measured; sky2.c:4896 maps
    // exactly 0x4000 bytes of it); BAR2 is the 256-byte I/O window
    // Linux claims but never uses (sky2.c:4846, hardware.md §1.2).
    let bar0 = read32(loc, 0x10);
    let bar1 = read32(loc, 0x14);
    let Some(mmio) = mem_bar_address(bar0, bar1) else {
        fatal("memory BAR missing or unassigned");
    };
    if mmio >= (1u64 << 32) {
        // entry.S identity-maps 4 GiB only — honest constraint, not a guess.
        fatal("memory BAR is above 4 GiB (outside the identity map)");
    }
    let bar2 = read32(loc, 0x18);
    if bar2 & 1 == 0 {
        // Measured as an I/O BAR; anything else means we decoded the
        // wrong function or the firmware left it unassigned.
        fatal("BAR2 is not an assigned I/O BAR");
    }
    let io_base = bar2 & !0x3;
    serial_println!(
        "sky2: mmio {mmio:#010x}, io {io_base:#06x} (BAR2 unused — Linux never touches it)"
    );

    // Enable I/O + memory decode and bus mastering (DMA), then verify
    // — the e1000 pattern, plus I/O because Linux's `pci_enable_device`
    // claims BAR2 too (sky2.c:4823).
    const CMD_IO_SPACE: u16 = 1 << 0; // PCI Local Bus Spec, cmd bit 0
    let cmd_dword = read32(loc, 0x04);
    let want = (CMD_MEMORY_SPACE | CMD_BUS_MASTER | CMD_IO_SPACE) as u32;
    write32(
        loc,
        0x04,
        (cmd_dword & 0xFFFF_0000) | (cmd_dword as u16 | want as u16) as u32,
    );
    let cmd_after = read32(loc, 0x04) as u16;
    if cmd_after & want as u16 != want as u16 {
        fatal("could not enable I/O + memory + bus master");
    }

    // --- Identification (sky2_init, sky2.c:3120-3226) --------------------
    // Enable all clocks through the window first, so a bad PCI read
    // cannot fake a dead chip (sky2.c:3125).
    mmio_write32(mmio, Y2_CFG_SPC + PCI_DEV_REG3, 0);
    mmio_write8(mmio, B0_CTST, CS_RST_CLR); // sky2.c:3127
    let chip_id = mmio_read8(mmio, B2_CHIP_ID); // sky2.c:3129
    let chip_rev = (mmio_read8(mmio, B2_MAC_CFG) & CFG_CHIP_R_MSK) >> 4; // sky2.c:3130
    if chip_id == 0xFF {
        fatal("BAR0 reads 0xff — MMIO not decoded");
    }
    if chip_id != CHIP_ID_YUKON_EC {
        fatal("unsupported chip id (only Yukon-EC / 88E8053 is driven)");
    }
    if chip_rev == CHIP_REV_YU_EC_A1 {
        // sky2.c:3157-3161 rejects this revision outright.
        fatal("unsupported revision Yukon-EC rev A1");
    }
    let pmd_type = mmio_read8(mmio, B2_PMD_TYP);
    if matches!(pmd_type, b'L' | b'S' | b'P') {
        // sky2.c:3211-3213: fibre PHY — out of scope (copper only).
        fatal("fibre PMD type — copper only");
    }
    // Port count (sky2.c:3216-3220); the 88E8053 is single-port, but
    // read it rather than assume.
    let hw_res = mmio_read8(mmio, B2_Y2_HW_RES);
    let clk_gate = mmio_read8(mmio, B2_Y2_CLK_GATE);
    let ports =
        if hw_res & CFG_DUAL_MAC_MSK == CFG_DUAL_MAC_MSK && clk_gate & Y2_STATUS_LNK2_INAC == 0 {
            2u8
        } else {
            1u8
        };
    if ports != 1 {
        fatal("dual-port chip — only port 0 is driven");
    }
    let ram_blocks = mmio_read8(mmio, B2_E_0); // 4 KiB blocks (sky2.c:3222)
    let ram_kb = u16::from(ram_blocks) * 4;
    serial_println!(
        "sky2: Yukon-2 EC chip revision {chip_rev} ({ports} port, ram buffer {ram_kb}K)"
    );

    // --- Status ring, allocated like sky2_probe (sky2.c:4908-4911) -------
    let st_le = alloc_frame("out of frames (status ring)");
    // SAFETY: fresh private frame; STATUS_SIZE × 8 = 4096 fits it and
    // the 4 KiB frame base is 8-byte aligned (the ring ABI).
    unsafe {
        write_bytes(st_le, 0, (STATUS_SIZE as usize) * 8);
    }

    // --- Chip reset (sky2_reset, sky2.c:3228-3421, port 0) --------------
    sky2_reset(mmio, st_le);

    // --- MAC address (sky2.c:4665: B2_MAC_1, the EEPROM loader's copy)
    let mut mac = [0u8; 6];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = mmio_read8(mmio, B2_MAC_1 + i as u32);
    }
    if !wire::mac_is_sane(&mac) {
        // Linux substitutes a random address (sky2.c:4671-4678); we
        // fail closed instead — no CSPRNG has run at probe time and a
        // silent random MAC would be untraceable on the wire.
        fatal("MAC from B2_MAC_1 is zero/broadcast/multicast");
    }
    if wire::locally_administered(&mac) {
        serial_println!("sky2: note: locally-administered MAC (U/L bit set)");
    }
    serial_println!(
        "sky2: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0],
        mac[1],
        mac[2],
        mac[3],
        mac[4],
        mac[5]
    );

    // --- DMA rings (frame allocator → physical, identity-mapped) ---------
    let tx_le = alloc_frame("out of frames (TX ring)").cast::<Le>();
    let tx_buf = alloc_frame("out of frames (TX buffer)");
    let rx_le = alloc_frame("out of frames (RX ring)").cast::<Le>();
    let rx_saved = alloc_frame("out of frames (RX scratch)");
    let mut rx_bufs = [core::ptr::null_mut(); RX_BUFFERS as usize];
    for buf in rx_bufs.iter_mut() {
        *buf = alloc_frame("out of frames (RX buffer)");
    }

    // tx_init (sky2.c:1108-1117): the first element initializes the
    // 64-bit *data*-address latch to 0 (`OP_ADDR64`, addr 0) — note
    // this latch is per queue and distinct from the prefetch unit's
    // ADDR_LO/HI (which point at the LE ring itself), so skipping it
    // would leave the first packet's upper address bits undefined.
    // prod advances past it; cons waits for the first TX report,
    // exactly like Linux (`tx_prod = 1`, `tx_cons = 0`).
    // SAFETY: fresh TX ring frame; slot 0 is ours until put_idx.
    unsafe {
        write_volatile(tx_le, Le::addr64(0));
    }

    let mut sky2 = Sky2 {
        mmio,
        mac,
        tx_le,
        tx_buf,
        tx_prod: 1,
        tx_cons: 0,
        tx_last_upper: 0,
        rx_le,
        rx_bufs,
        rx_saved,
        rx_saved_len: 0,
        rx_put: 0,
        rx_status_next: 0,
        rx_dropped: 0,
        ram_buffer: ram_blocks != 0,
        st_le,
        st_idx: 0,
    };

    // --- MAC/PHY/FIFO bring-up (sky2_hw_up → sky2_mac_init) -------------
    sky2.mac_init();
    // RAM buffer partition (sky2_hw_up, sky2.c:1673-1694) when the
    // chip reports internal RAM.
    if let Some(part) = wire::ram_buffer_layout(ram_kb) {
        sky2.ramset(Q_R1, 0, part.rx_space_kb);
        sky2.ramset(Q_XA1, part.rx_space_kb, part.tx_space_kb);
        // Sync TX queue unused (sky2.c:1692-1694).
        mmio_write8(mmio, rb_addr(Q_XS1, RB_CTRL), RB_RST_SET);
    }

    // --- TX queue: qset + prefetch (sky2.c:1696-1710) -------------------
    sky2.qset(Q_XA1);
    sky2.prefetch_init(Q_XA1, tx_le as u64, TX_RING - 1);

    // --- RX queue: qset, prefetch, buffers, truncation (sky2_rx_start) ---
    sky2.rx_start();

    // --- Link: wait for auto-negotiation, then sky2_link_up -------------
    let deadline = crate::clock::now_ms() + LINK_DEADLINE_MS;
    let link = loop {
        let st = or_fatal(sky2.smi_read(PHY_MARV_PHY_STAT));
        if let Some(resolved) = wire::resolve_link(st) {
            break resolved;
        }
        if crate::clock::now_ms() > deadline {
            fatal("no link after 10000 ms (cable connected?)");
        }
        core::hint::spin_loop();
    };
    // sky2_autoneg_done's flow-control negotiation (sky2.c:2247-2284).
    let advert = or_fatal(sky2.smi_read(PHY_MARV_AUNE_ADV));
    let lpa = or_fatal(sky2.smi_read(PHY_MARV_AUNE_LP));
    if lpa & PHY_M_AN_RF != 0 {
        fatal("link partner reported remote fault");
    }
    let flow = wire::flow_control(advert, lpa, link);
    let flow_name = match flow {
        wire::FlowControl::None => "none",
        wire::FlowControl::Tx => "tx",
        wire::FlowControl::Rx => "rx",
        wire::FlowControl::Both => "both",
    };
    sky2.link_up(link, flow);
    serial_println!(
        "sky2: link up, {} Mbps, {} duplex, flow control {flow_name}",
        link.speed_mbps,
        if link.full_duplex { "full" } else { "half" }
    );

    // Polled mode: mask every card-side interrupt source at the device
    // too (sky2_close writes 0 — sky2.c:2123); only IRQ0 is unmasked
    // on the PIC anyway. Read back as a write barrier (the pattern of
    // sky2.c:1763-1764).
    mmio_write32(mmio, B0_IMSK, 0);
    let _ = mmio_read32(mmio, B0_IMSK);

    serial_println!(
        "sky2: rings up — {TX_RING} TX + {RX_LE_RING} RX LEs, {RX_BUFFERS} RX buffers, {STATUS_SIZE} status"
    );
    serial_println!("SKY2_OK"); // printed only on real hardware (module docs)

    Some(sky2)
}

/// `sky2_reset` (sky2.c:3228-3421) for port 0, minus the chip-family
/// blocks that do not apply to plain Yukon-EC (ASF-CPU on EX/Supreme,
/// PSM on Optima — sky2.c:3235-3251, 3292-3345). Every write below is
/// copied from the cited line.
fn sky2_reset(mmio: u64, st_le: *mut u8) {
    // ASF off (non-EX/Supreme branch, sky2.c:3247-3253).
    mmio_write8(mmio, B28_Y2_ASF_STAT_CMD, Y2_ASF_RESET);
    mmio_write16(mmio, B0_CTST, Y2_ASF_DISABLE);
    // Software reset (sky2.c:3255-3256).
    mmio_write8(mmio, B0_CTST, CS_RST_SET);
    mmio_write8(mmio, B0_CTST, CS_RST_CLR);
    // Open the PCI-config window and clear sticky PCI status errors
    // (sky2.c:3259-3265).
    mmio_write8(mmio, B2_TST_CTRL1, TST_CFG_WRITE_ON);
    let pci_status = mmio_read16(mmio, Y2_CFG_SPC + PCI_STATUS_OFF);
    mmio_write16(
        mmio,
        Y2_CFG_SPC + PCI_STATUS_OFF,
        pci_status | PCI_STATUS_ERROR_BITS,
    );
    mmio_write8(mmio, B0_CTST, CS_MRST_CLR);
    // PCIe AER (sky2.c:3268-3276): the MacBook's NIC is a measured
    // Express v1 endpoint (hardware.md §1.1), so take the `pci_is_pcie`
    // branch: W1C the uncorrectable errors, and only *add* the PCIe
    // error bit to the HW-error mask if it is not stuck high.
    mmio_write32(mmio, Y2_CFG_AER + PCI_ERR_UNCOR_STATUS, 0xFFFF_FFFF);
    let mut hwe_mask = Y2_HWE_ALL_MASK;
    if mmio_read32(mmio, B0_HWE_ISRC) & Y2_IS_PCI_EXP != 0 {
        serial_println!("sky2: ignoring stuck PCIe error-report bit (sky2.c:3274)");
    } else {
        hwe_mask |= Y2_IS_PCI_EXP;
    }
    // Power on (sky2_power_on, sky2.c:197-206 — the
    // SKY2_HW_ADV_POWER_CTL block is not taken by plain EC).
    mmio_write8(mmio, B0_POWER_CTRL, PC_POWER_VCC);
    mmio_write32(mmio, B2_Y2_CLK_CTRL, Y2_CLK_DIV_DIS);
    mmio_write8(mmio, B2_Y2_CLK_GATE, 0);
    mmio_write16(mmio, B0_CTST, Y2_LED_STAT_ON);
    mmio_write8(mmio, B2_TST_CTRL1, TST_CFG_WRITE_OFF); // sky2.c:3280

    // Per-port link reset (sky2.c:3282-3284).
    mmio_write8(mmio, SK_GMAC_LINK_CTRL, GMLC_RST_SET);
    mmio_write8(mmio, SK_GMAC_LINK_CTRL, GMLC_RST_CLR);

    // Quiesce: I2C noise, all three hardware timers, the descriptor
    // poll timer and the RX timestamp timer (sky2.c:3347-3361).
    mmio_write32(mmio, B2_I2C_IRQ, 1);
    mmio_write8(mmio, B2_TI_CTRL, TIM_STOP);
    mmio_write8(mmio, B2_TI_CTRL, TIM_CLR_IRQ);
    mmio_write32(mmio, B28_DPT_CTRL, DPT_STOP);
    mmio_write8(mmio, GMAC_TI_ST_CTRL, GMT_ST_STOP);
    mmio_write8(mmio, GMAC_TI_ST_CTRL, GMT_ST_CLR_IRQ);

    // TX arbiter on (sky2.c:3363-3365).
    mmio_write8(mmio, SK_TXA_CTRL, TXA_ENA_ARB);

    // RAM-interface reset + all twelve timeouts (sky2.c:3367-3383).
    mmio_write8(mmio, B3_RI_CTRL, RI_RST_CLR);
    for reg in B3_RI_WTO_BASE..B3_RI_WTO_BASE + 12 {
        mmio_write8(mmio, reg, SK_RI_TO_53);
    }

    // Hardware-error interrupt *mask* (sky2.c:3386): masked sources
    // are harmless in polled mode, and this mirrors Linux exactly.
    mmio_write32(mmio, B0_HWE_IMSK, hwe_mask);

    // GMAC reset (sky2_gmac_reset, sky2.c:284-298): mask MAC IRQs,
    // clear the multicast hash, pass unicast+multicast up the stack.
    mmio_write8(mmio, SK_GMAC_IRQ_MSK, 0);
    for i in 0..4u32 {
        mmio_write16(mmio, gma(GM_MC_ADDR_H1 + i * 4), 0);
    }
    let rx_ctrl = mmio_read16(mmio, gma(GM_RX_CTRL));
    mmio_write16(
        mmio,
        gma(GM_RX_CTRL),
        rx_ctrl | GM_RXCR_UCF_ENA | GM_RXCR_MCF_ENA,
    );

    // Status unit (sky2.c:3390-3421): reset, point it at our ring,
    // arm the watermarks and the three flush timers, go operational.
    // The timers are what make completion visible in *polled* mode —
    // they flush the status FIFO into the ring regardless of B0_IMSK.
    mmio_write32(mmio, STAT_CTRL, SC_STAT_RST_SET);
    mmio_write32(mmio, STAT_CTRL, SC_STAT_RST_CLR);
    mmio_write32(mmio, STAT_LIST_ADDR_LO, st_le as u32);
    mmio_write32(mmio, STAT_LIST_ADDR_HI, (st_le as u64 >> 32) as u32);
    mmio_write16(mmio, STAT_LAST_IDX, STATUS_SIZE - 1);
    mmio_write16(mmio, STAT_TX_IDX_TH, 10);
    mmio_write8(mmio, STAT_FIFO_WM, 16);
    mmio_write8(mmio, STAT_FIFO_ISR_WM, 16);
    let (tx_ini, isr_ini, lev_ini) = wire::status_timer_inis();
    mmio_write32(mmio, STAT_TX_TIMER_INI, tx_ini);
    mmio_write32(mmio, STAT_ISR_TIMER_INI, isr_ini);
    mmio_write32(mmio, STAT_LEV_TIMER_INI, lev_ini);
    mmio_write32(mmio, STAT_CTRL, SC_STAT_OP_ON);
    mmio_write8(mmio, STAT_TX_TIMER_CTRL, TIM_START);
    mmio_write8(mmio, STAT_LEV_TIMER_CTRL, TIM_START);
    mmio_write8(mmio, STAT_ISR_TIMER_CTRL, TIM_START);
}

impl Sky2 {
    // --- SMI (MDIO) access — sky2.c:152-206, bounded by PHY_POLLS -------

    /// Read one PHY register over SMI. `Err` on a dead bus (`0xffff`)
    /// or a poll timeout — callers on the boot-critical path turn
    /// that into `FATAL: sky2: …`.
    fn smi_read(&self, reg: u8) -> Result<u16, &'static str> {
        mmio_write16(
            self.mmio,
            gma(GM_SMI_CTRL),
            wire::smi_ctrl(PHY_ADDR_MARV, reg, true),
        );
        for _ in 0..PHY_POLLS {
            let ctrl = mmio_read16(self.mmio, gma(GM_SMI_CTRL));
            if wire::smi_dead(ctrl) {
                return Err("SMI read path dead (ctrl = 0xffff)");
            }
            if wire::smi_read_done(ctrl) {
                return Ok(mmio_read16(self.mmio, gma(GM_SMI_DATA)));
            }
            core::hint::spin_loop();
        }
        Err("SMI read timed out")
    }

    /// Write one PHY register over SMI; same bounds as [`Self::smi_read`].
    fn smi_write(&self, reg: u8, val: u16) -> Result<(), &'static str> {
        mmio_write16(self.mmio, gma(GM_SMI_DATA), val);
        mmio_write16(
            self.mmio,
            gma(GM_SMI_CTRL),
            wire::smi_ctrl(PHY_ADDR_MARV, reg, false),
        );
        for _ in 0..PHY_POLLS {
            let ctrl = mmio_read16(self.mmio, gma(GM_SMI_CTRL));
            if wire::smi_dead(ctrl) {
                return Err("SMI write path dead (ctrl = 0xffff)");
            }
            if !wire::smi_busy(ctrl) {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("SMI write timed out")
    }

    // --- MAC/PHY bring-up (sky2_mac_init, sky2.c:898-1035) --------------

    /// GMAC/GPHY reset, PHY power-up + id check + auto-negotiation
    /// setup, MIB clear, MAC addresses, TX/RX parameters, MAC FIFOs
    /// — the port-0 subset of `sky2_mac_init`.
    fn mac_init(&self) {
        let mmio = self.mmio;
        // GPHY/GMAC reset + stale IRQ sources (sky2.c:902-914).
        mmio_write8(mmio, SK_GPHY_CTRL, GPC_RST_SET);
        mmio_write8(mmio, SK_GPHY_CTRL, GPC_RST_CLR);
        mmio_write8(mmio, SK_GMAC_CTRL, GMC_RST_CLR);
        let _ = mmio_read16(mmio, SK_GMAC_IRQ_SRC);
        mmio_write8(mmio, SK_GMAC_IRQ_MSK, GMAC_DEF_MSK);

        // PHY power-up (sky2_phy_power_up, sky2.c:696-716): clear the
        // PHY power-down bit through the PCI window; the plain-EC path
        // takes no further branch (sky2.c:712-714).
        mmio_write8(mmio, B2_TST_CTRL1, TST_CFG_WRITE_ON);
        let reg1 = mmio_read32(mmio, Y2_CFG_SPC + PCI_DEV_REG1);
        mmio_write32(mmio, Y2_CFG_SPC + PCI_DEV_REG1, reg1 & !PCI_Y2_PHY1_POWD);
        mmio_write8(mmio, B2_TST_CTRL1, TST_CFG_WRITE_OFF);
        let _ = mmio_read32(mmio, Y2_CFG_SPC + PCI_DEV_REG1); // read-back barrier (sky2.c:711)

        // Prove the SMI path with the PHY ids before trusting it for
        // the whole init (sky2.c:905-910 does the same cross-check on
        // Yukon-XL). ID0 must be Marvell's OUI; ID1 is reported.
        let id0 = or_fatal(self.smi_read(PHY_MARV_ID0));
        let id1 = or_fatal(self.smi_read(PHY_MARV_ID1));
        if !wire::is_marvell_phy(id0) {
            fatal("PHY ID0 is not a Marvell OUI — SMI broken?");
        }
        if !wire::is_yukon_ec_phy(id1) {
            // Not fatal: any Marvell PHY is driven the same way here;
            // print the numeric id so a physical log can record it.
            serial_println!(
                "sky2: PHY id {id0:#06x}/{id1:#06x} (not the expected {:#06x} — continuing)",
                wire::PHY_ID1_YUKON_EC
            );
        } else {
            serial_println!("sky2: PHY id {id0:#06x}/{id1:#06x}");
        }

        self.phy_init();

        // MIB clear (sky2.c:935-941): latch clear mode, read every
        // counter, restore.
        let mib = mmio_read16(mmio, gma(GM_PHY_ADDR));
        mmio_write16(mmio, gma(GM_PHY_ADDR), mib | GM_PAR_MIB_CLR);
        let mut reg = GM_MIB_CNT_BASE;
        while reg <= GM_MIB_CNT_END {
            let _ = mmio_read16(mmio, gma(reg));
            reg += 4;
        }
        mmio_write16(mmio, gma(GM_PHY_ADDR), mib);

        // TX/RX control and parameters (sky2.c:944-991).
        mmio_write16(mmio, gma(GM_TX_CTRL), wire::tx_mac_ctrl());
        mmio_write16(mmio, gma(GM_RX_CTRL), wire::rx_mac_ctrl());
        mmio_write16(mmio, gma(GM_TX_FLOW_CTRL), 0xffff); // sky2.c:952
        mmio_write16(mmio, gma(GM_TX_PARAM), wire::tx_param());
        mmio_write16(mmio, gma(GM_SERIAL_MODE), wire::serial_mode());
        self.gma_set_addr(GM_SRC_ADDR_2L); // data address (sky2.c:978)
        self.gma_set_addr(GM_SRC_ADDR_1L); // pause address (sky2.c:981)
        // Ignore counter overflows (sky2.c:988-991).
        mmio_write16(mmio, gma(GM_TX_IRQ_MSK), 0);
        mmio_write16(mmio, gma(GM_RX_IRQ_MSK), 0);
        mmio_write16(mmio, gma(GM_TR_IRQ_MSK), 0);

        // RX MAC FIFO (sky2.c:963-1006): reset, operational + flush
        // mode, flush on any error, threshold 0xa+1 (the "magic
        // mystery workaround" of sky2.c:1000-1006).
        mmio_write8(mmio, SK_RX_GMF_CTRL_T, GMF_RST_CLR);
        mmio_write32(mmio, SK_RX_GMF_CTRL_T, GMF_OPER_ON | GMF_RX_F_FL_ON);
        mmio_write16(mmio, SK_RX_GMF_FL_MSK, wire::GMR_FS_ANY_ERR as u16);
        mmio_write16(mmio, SK_RX_GMF_FL_THR, RX_GMF_FL_THR_DEF + 1);

        // TX MAC FIFO (sky2.c:1008-1012).
        mmio_write8(mmio, SK_TX_GMF_CTRL_T, GMF_RST_CLR);
        mmio_write16(mmio, SK_TX_GMF_CTRL_T, GMF_OPER_ON as u16);

        // Chips without an internal RAM buffer control pause at the
        // MAC level (sky2.c:1014-1024). `sky2_set_tx_stfwd` for plain
        // Yukon-EC at MTU 1500 ends in TX_STFW_ENA (sky2.c:892-893).
        if !self.ram_buffer {
            mmio_write16(mmio, SK_RX_GMF_UP_THR, 1024 / 8);
            mmio_write16(mmio, SK_RX_GMF_LP_THR, 768 / 8);
            mmio_write32(mmio, SK_TX_GMF_CTRL_T, TX_STFW_ENA);
        }
    }

    /// Auto-negotiation setup for copper gigabit (the EC subset of
    /// `sky2_phy_init`, sky2.c:326-690): EXT_CTRL clock/downshift,
    /// PHY_CTRL energy-detect/crossover, advertisement of 10/100/1000
    /// with pause both directions, restart AN. LED programming is
    /// skipped (cosmetic, sky2.c:474-623; module docs).
    fn phy_init(&self) {
        let ext = or_fatal(self.smi_read(PHY_MARV_EXT_CTRL));
        or_fatal(self.smi_write(PHY_MARV_EXT_CTRL, wire::phy_ext_ctrl_ec(ext)));
        let ctrl = or_fatal(self.smi_read(PHY_MARV_PHY_CTRL));
        or_fatal(self.smi_write(PHY_MARV_PHY_CTRL, wire::phy_specific_ctrl_gig(ctrl)));

        // GM_GP_CTRL ← 0: leave auto-update of speed/duplex/flow
        // control enabled (with SKY2_FLAG_AUTO_PAUSE the pause bits
        // ride in the advertisement instead — sky2.c:455-461).
        mmio_write16(self.mmio, gma(GM_GP_CTRL), 0);
        // sky2.c:458-470: 1000-t control, advertisement, then the
        // PHY control word that restarts auto-negotiation.
        or_fatal(self.smi_write(PHY_MARV_1000T_CTRL, wire::phy_1000t_ctrl()));
        or_fatal(self.smi_write(PHY_MARV_AUNE_ADV, wire::phy_advertisement()));
        or_fatal(self.smi_write(PHY_MARV_CTRL, wire::phy_ctrl_autoneg()));
        // sky2.c:677-682: mask for "AN complete" (we poll
        // PHY_MARV_PHY_STAT directly; the mask only arms the latch
        // the future IRQ milestone will read).
        or_fatal(self.smi_write(PHY_MARV_INT_MASK, PHY_M_IS_AN_COMPL));
    }

    /// Write the station address into GM_SRC_ADDR_{1,2}L/M/H —
    /// `gma_set_addr` (sky2.h:2385-2392): three 16-bit little-endian
    /// halves four register-steps apart.
    fn gma_set_addr(&self, reg: u32) {
        for half in 0..3u32 {
            let word = u16::from_le_bytes([
                self.mac[(2 * half) as usize],
                self.mac[(2 * half + 1) as usize],
            ]);
            mmio_write16(self.mmio, gma(reg + half * 4), word);
        }
    }

    /// `sky2_ramset` (sky2.c:1037-1075): assign `[start_kb,
    /// start_kb+space_kb)` of the internal RAM to one queue, with the
    /// RX thresholds (composed by `sky2-wire`) or TX store-and-forward.
    fn ramset(&self, queue: u16, start_kb: u16, space_kb: u16) {
        // KiB → qwords (×1024/8), sky2.c:1041-1042.
        let start = u32::from(start_kb) * 128;
        let space = u32::from(space_kb) * 128;
        let end = start + space - 1;
        mmio_write8(self.mmio, rb_addr(queue, RB_CTRL), RB_RST_CLR);
        mmio_write32(self.mmio, rb_addr(queue, RB_START), start);
        mmio_write32(self.mmio, rb_addr(queue, RB_END), end);
        mmio_write32(self.mmio, rb_addr(queue, RB_WP), start);
        mmio_write32(self.mmio, rb_addr(queue, RB_RP), start);
        if queue == Q_R1 {
            let t = wire::ram_thresholds(space);
            mmio_write32(self.mmio, rb_addr(queue, RB_RX_UTHP), t.upper_high);
            mmio_write32(self.mmio, rb_addr(queue, RB_RX_LTHP), t.lower_high);
            mmio_write32(self.mmio, rb_addr(queue, RB_RX_UTPP), t.upper_pause);
            mmio_write32(self.mmio, rb_addr(queue, RB_RX_LTPP), t.lower_pause);
        } else {
            // "Tx FIFO is only 1K on Yukon" (sky2.c:1068-1070).
            mmio_write8(self.mmio, rb_addr(queue, RB_CTRL), RB_ENA_STFWD);
        }
        mmio_write8(self.mmio, rb_addr(queue, RB_CTRL), RB_ENA_OP_MD);
        let _ = mmio_read8(self.mmio, rb_addr(queue, RB_CTRL)); // sky2.c:1074
    }

    /// `sky2_qset` (sky2.c:1077-1084): BMU reset → init → FIFO on →
    /// default watermark.
    fn qset(&self, queue: u16) {
        mmio_write32(self.mmio, q_addr(queue, Q_CSR), BMU_CLR_RESET);
        mmio_write32(self.mmio, q_addr(queue, Q_CSR), BMU_OPER_INIT);
        mmio_write32(self.mmio, q_addr(queue, Q_CSR), BMU_FIFO_OP_ON);
        mmio_write32(self.mmio, q_addr(queue, Q_WM), BMU_WM_DEFAULT);
    }

    /// `sky2_prefetch_init` (sky2.c:1089-1103): hand the queue its
    /// list-element ring address and last index, switch it on, read
    /// back as a write barrier.
    fn prefetch_init(&self, queue: u16, ring_dma: u64, last: u16) {
        let mmio = self.mmio;
        mmio_write32(mmio, y2_qaddr(queue, PREF_UNIT_CTRL), PREF_UNIT_RST_SET);
        mmio_write32(mmio, y2_qaddr(queue, PREF_UNIT_CTRL), PREF_UNIT_RST_CLR);
        mmio_write32(
            mmio,
            y2_qaddr(queue, PREF_UNIT_ADDR_HI),
            (ring_dma >> 32) as u32,
        );
        mmio_write32(mmio, y2_qaddr(queue, PREF_UNIT_ADDR_LO), ring_dma as u32);
        mmio_write16(mmio, y2_qaddr(queue, PREF_UNIT_LAST_IDX), last);
        mmio_write32(mmio, y2_qaddr(queue, PREF_UNIT_CTRL), PREF_UNIT_OP_ON);
        let _ = mmio_read32(mmio, y2_qaddr(queue, PREF_UNIT_CTRL));
    }

    /// Publish the queue's producer index — `sky2_put_idx`
    /// (sky2.c:1126-1131): write barrier, then the 16-bit register.
    fn put_idx(&self, queue: u16, idx: u16) {
        fence(Ordering::SeqCst);
        mmio_write16(self.mmio, y2_qaddr(queue, PREF_UNIT_PUT_IDX), idx);
    }

    /// `sky2_rx_start` (sky2.c:1518-1571): qset, PCIe watermark,
    /// prefetch the RX ring, submit one element pair per buffer, arm
    /// oversize truncation, publish the producer index.
    fn rx_start(&mut self) {
        let mmio = self.mmio;
        self.qset(Q_R1);
        // "On PCI express lowering the watermark gives better
        // performance" (sky2.c:1527-1529) — the MacBook's NIC is a
        // measured PCIe endpoint (hardware.md §1.1).
        mmio_write32(mmio, q_addr(Q_R1, Q_WM), BMU_WM_PEX);
        self.prefetch_init(Q_R1, self.rx_le as u64, RX_LE_RING - 1);

        // Fill: each buffer gets an OP_ADDR64 (upper half = 0 — this
        // also initializes the queue's data-address latch, exactly as
        // sky2_rx_add does on 64-bit builds, sky2.c:1184-1197) and an
        // OP_PACKET element of RX_DATA_SIZE bytes.
        for i in 0..RX_BUFFERS {
            let buf = match self.rx_bufs.get(usize::from(i)) {
                Some(&b) => b,
                None => fatal("rx buffer index out of range"),
            };
            // SAFETY: rx_le ring frame (see struct docs); rx_put stays
            // < RX_LE_RING (only 2 × RX_BUFFERS = 64 elements are
            // written before the first wrap, and wraps only recycle
            // slots the prefetch unit has consumed).
            unsafe {
                write_volatile(self.rx_le.add(usize::from(self.rx_put)), Le::addr64(0));
                write_volatile(
                    self.rx_le
                        .add(usize::from(next_index(self.rx_put, RX_LE_RING))),
                    Le::rx_buffer(buf as u32, RX_DATA_SIZE),
                );
            }
            self.rx_put = next_index(next_index(self.rx_put, RX_LE_RING), RX_LE_RING);
        }

        // Oversize truncation (sky2.c:1554-1571): "The receiver hangs
        // if it receives frames larger than the packet buffer" —
        // program the 9-bit threshold, or disable truncation if the
        // threshold cannot be represented (never at MTU 1500).
        match wire::rx_truncation_threshold(MTU) {
            Some(thresh) => {
                mmio_write16(mmio, SK_RX_GMF_TR_THR, thresh);
                mmio_write32(mmio, SK_RX_GMF_CTRL_T, RX_TRUNC_ON);
            }
            None => mmio_write32(mmio, SK_RX_GMF_CTRL_T, RX_TRUNC_OFF),
        }

        // Tell the chip about the buffers (sky2_rx_update, sky2.c:1480-1483).
        self.put_idx(Q_R1, self.rx_put);
    }

    /// `sky2_link_up` (sky2.c:2171-2201): IPG for the negotiated
    /// speed, enable RX/TX at the MAC, arm the PHY status mask, turn
    /// the link LED on, and enable pause if the partner negotiated it
    /// (`sky2_autoneg_done`, sky2.c:2280-2283).
    fn link_up(&self, link: wire::ResolvedLink, flow: wire::FlowControl) {
        let mmio = self.mmio;
        // sky2_set_ipg (sky2.c:773-785).
        let mode = mmio_read16(mmio, gma(GM_SERIAL_MODE));
        mmio_write16(
            mmio,
            gma(GM_SERIAL_MODE),
            (mode & !0x1f) | wire::ipg_for_speed(link.speed_mbps),
        );
        // sky2_enable_rx_tx (sky2.c:787-794).
        let gp = mmio_read16(mmio, gma(GM_GP_CTRL));
        mmio_write16(mmio, gma(GM_GP_CTRL), gp | GM_GPCR_RX_ENA | GM_GPCR_TX_ENA);
        // PHY status mask + link LED (sky2.c:2191, 2196-2197).
        or_fatal(self.smi_write(PHY_MARV_INT_MASK, PHY_M_DEF_MSK));
        mmio_write8(mmio, SK_LNK_LED_REG, LINK_LED_ON);
        // Flow control at the MAC (sky2.c:2280-2283).
        let pause = if matches!(flow, wire::FlowControl::Tx | wire::FlowControl::Both) {
            GMC_PAUSE_ON
        } else {
            GMC_PAUSE_OFF
        };
        mmio_write8(mmio, SK_GMAC_CTRL, pause);
    }

    // --- Status ring (the polled completion path) ------------------------

    /// Consume the next status-ring element, or `None` when the chip
    /// has not written one yet. The chip writes the fields first and
    /// the owner bit last (the `rmb()` contract of sky2.c:2645-2651),
    /// so the opcode byte is read first, then a fence, then the rest.
    fn next_status(&mut self) -> Option<wire::StatusEntry> {
        let idx = self.st_idx;
        // SAFETY: our status ring (STATUS_SIZE × 8 = one frame, 8-byte
        // aligned, identity-mapped); `idx` < STATUS_SIZE by the ring
        // mask.
        let p = unsafe { self.st_le.add(usize::from(idx) * 8) };
        // SAFETY: as above; volatile byte read of device-updated memory.
        let opcode = unsafe { read_volatile(p.add(7)) };
        if opcode & wire::HW_OWNER == 0 {
            return None; // slot not (yet) written by the chip
        }
        fence(Ordering::SeqCst);
        let mut bytes = [0u8; 8];
        bytes[7] = opcode;
        // SAFETY: same slot; the owner bit proved the entry is fully
        // written, and the chip will not touch it again until the
        // ring wraps past a slot we have consumed.
        for (i, slot) in bytes[..7].iter_mut().enumerate() {
            *slot = unsafe { read_volatile(p.add(i)) };
        }
        let entry = wire::parse_status(&bytes)?;
        // SAFETY: same slot; returning ownership for the next wrap
        // (`le->opcode = 0`, sky2.c:2651).
        unsafe { write_volatile(p.add(7), 0u8) };
        self.st_idx = next_index(idx, STATUS_SIZE);
        Some(entry)
    }

    /// Re-submit one RX buffer: an `OP_ADDR64` + `OP_PACKET` element
    /// pair at `rx_put`, then publish — the `sky2_rx_submit` +
    /// `sky2_rx_update` pair (sky2.c:1184-1197, 1480-1483).
    fn resubmit_rx(&mut self, buf_idx: u8) {
        let buf = match self.rx_bufs.get(usize::from(buf_idx)) {
            Some(&b) => b,
            None => fatal("rx buffer index out of range"),
        };
        let put = self.rx_put;
        let second = next_index(put, RX_LE_RING);
        // SAFETY: rx_le ring frame; `put`/`second` are inside it (the
        // ring mask wraps) and only RX_BUFFERS×2 slots are ever
        // outstanding — the prefetch unit has consumed every slot we
        // are about overwrite by the time its buffer is re-submitted.
        unsafe {
            write_volatile(self.rx_le.add(usize::from(put)), Le::addr64(0));
            write_volatile(
                self.rx_le.add(usize::from(second)),
                Le::rx_buffer(buf as u32, RX_DATA_SIZE),
            );
        }
        self.rx_put = next_index(second, RX_LE_RING);
        self.put_idx(Q_R1, self.rx_put);
    }

    /// Acknowledge a fully drained status burst (`SC_STAT_CLR_IRQ`,
    /// sky2.c:2688 — written only when we actually consumed an
    /// element, as Linux does).
    fn ack_status(&self, processed: bool) {
        if processed {
            mmio_write32(self.mmio, STAT_CTRL, SC_STAT_CLR_IRQ);
        }
    }

    /// Drain the status ring for a waiting transmit: reclaim TX slots
    /// and park RX frames in the scratch slot (drop when it is full —
    /// module docs). Never returns with a TX entry still pending.
    fn drain_for_tx(&mut self) {
        let mut processed = false;
        while let Some(entry) = self.next_status() {
            processed = true;
            match entry {
                wire::StatusEntry::Rx { len } => {
                    let b = self.rx_status_next;
                    self.rx_status_next = next_buffer(b);
                    if let Some(n) = len {
                        if self.rx_saved_len == 0 {
                            let n = core::cmp::min(usize::from(n), usize::from(RX_DATA_SIZE));
                            // SAFETY: rx_saved is our private frame
                            // (BUF_BYTES ≥ RX_DATA_SIZE ≥ n).
                            unsafe {
                                core::ptr::copy_nonoverlapping(
                                    self.rx_bufs[usize::from(b)],
                                    self.rx_saved,
                                    n,
                                );
                            }
                            self.rx_saved_len = n;
                        } else {
                            // Scratch holds an older frame: this one
                            // would block TX completions behind it in
                            // the status FIFO — drop it, counted.
                            self.rx_dropped = self.rx_dropped.saturating_add(1);
                        }
                    }
                    self.resubmit_rx(b);
                }
                wire::StatusEntry::TxComplete { next } => self.tx_cons = next,
                wire::StatusEntry::Ignored => {}
            }
        }
        self.ack_status(processed);
    }

    // --- Public driver API (the stack's `Nic` calls these) --------------

    /// The station MAC address read at probe time.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Send one Ethernet frame and wait — bounded — for the status
    /// ring to report it done (synchronous TX, module docs).
    pub fn transmit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.len() > BUF_BYTES {
            return Err("frame larger than the TX buffer");
        }
        // SAFETY: `tx_buf` is our private frame and `frame.len()`
        // was checked above, so the copy cannot leave the 4 KiB frame.
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), self.tx_buf, frame.len());
        }
        let addr = self.tx_buf as u64;
        let upper = (addr >> 32) as u32;
        let mut slot = self.tx_prod;
        // Emit an OP_ADDR64 element when the upper half changes
        // (sky2.c:1849-1856). Identity-mapped frames are < 4 GiB and
        // the latch starts at 0, so this never fires today — kept
        // because it is the documented behaviour of `sky2_xmit_frame`.
        if upper != self.tx_last_upper {
            // SAFETY: TX ring; `slot` is ours until put_idx below.
            unsafe {
                write_volatile(self.tx_le.add(usize::from(slot)), Le::addr64(upper));
            }
            self.tx_last_upper = upper;
            slot = next_index(slot, TX_RING);
        }
        // SAFETY: as above; the single buffer is exclusively ours
        // until the completion wait returns.
        unsafe {
            write_volatile(
                self.tx_le.add(usize::from(slot)),
                Le::tx_packet(addr as u32, frame.len() as u16),
            );
        }
        slot = next_index(slot, TX_RING);
        self.tx_prod = slot;
        self.put_idx(Q_XA1, self.tx_prod);

        for _ in 0..TX_POLLS {
            self.drain_for_tx();
            if self.tx_cons == self.tx_prod {
                return Ok(()); // chip is done reading our buffer
            }
            core::hint::spin_loop();
        }
        Err("TX descriptor never reported done")
    }

    /// Poll for one received frame: the oldest frame first (a scratch
    /// frame saved during a transmit wait precedes anything the ring
    /// still holds), then the status ring. Copies into `buf` and
    /// returns the length, or `None` when nothing has arrived.
    pub fn receive(&mut self, buf: &mut [u8]) -> Option<usize> {
        if self.rx_saved_len > 0 {
            let n = core::cmp::min(self.rx_saved_len, buf.len());
            // SAFETY: rx_saved is our private frame; rx_saved_len ≤
            // RX_DATA_SIZE ≤ BUF_BYTES and n ≤ buf.len().
            unsafe {
                core::ptr::copy_nonoverlapping(self.rx_saved, buf.as_mut_ptr(), n);
            }
            self.rx_saved_len = 0;
            crate::entropy::note_rx();
            return Some(n);
        }
        let mut processed = false;
        while let Some(entry) = self.next_status() {
            processed = true;
            match entry {
                wire::StatusEntry::Rx { len: Some(n) } => {
                    let b = self.rx_status_next;
                    self.rx_status_next = next_buffer(b);
                    let n = core::cmp::min(usize::from(n), usize::from(RX_DATA_SIZE));
                    let len = core::cmp::min(n, buf.len());
                    // SAFETY: rx_bufs[b] is our private 4 KiB frame;
                    // the chip DMA'd at most RX_DATA_SIZE bytes into
                    // it (element length + truncation threshold), and
                    // len ≤ buf.len().
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.rx_bufs[usize::from(b)],
                            buf.as_mut_ptr(),
                            len,
                        );
                    }
                    self.resubmit_rx(b);
                    self.ack_status(processed);
                    crate::entropy::note_rx();
                    return Some(len);
                }
                wire::StatusEntry::Rx { len: None } => {
                    // Error or length mismatch (sky2.c:2618-2639):
                    // drop the frame, re-submit the buffer.
                    let b = self.rx_status_next;
                    self.rx_status_next = next_buffer(b);
                    self.resubmit_rx(b);
                }
                wire::StatusEntry::TxComplete { next } => self.tx_cons = next,
                wire::StatusEntry::Ignored => {}
            }
        }
        self.ack_status(processed);
        None
    }

    /// Live link state, read from `PHY_MARV_PHY_STAT` (the shell's
    /// `netinfo`): `Unknown` when the SMI bus does not answer.
    pub fn link(&self) -> LinkState {
        match self.smi_read(PHY_MARV_PHY_STAT) {
            Ok(st) => match wire::resolve_link(st) {
                Some(l) => LinkState::Up {
                    speed_mbps: l.speed_mbps,
                    full_duplex: l.full_duplex,
                },
                None => LinkState::Down,
            },
            Err(_) => LinkState::Unknown,
        }
    }

    /// Frames dropped because the RX scratch slot was occupied
    /// during a transmit wait (module docs).
    pub fn rx_dropped(&self) -> u32 {
        self.rx_dropped
    }
}
