# Hardware notes — Marvell 88E8053 GbE (sky2) and keyboard input

Research notes for two future driver milestones:

1. a **Marvell 88E8053 GbE driver** (Linux `sky2` register/protocol reference) for the real
   MacBook2,1 — today the OS only has an Intel **e1000** driver that works in QEMU;
2. a **keyboard input driver** (i8042/PS/2 first for QEMU, USB HID later for real hardware) —
   today the console only reads the serial port (`kernel/src/serial.rs:57` `read_byte`,
   used from the input loop at `kernel/src/main.rs:165`).

**Citation convention.** `[sky2.c:NNNN]` / `[sky2.h:NNNN]` are line numbers of
`drivers/net/ethernet/marvell/sky2.c` / `sky2.h` from torvalds/linux **master**, fetched
2026-11 (raw URLs in §Sources). Repo references (`pic.rs`, `idt.rs`, …) are this checkout.
Anything I could not verify from a primary source is marked **[unverified]** explicitly —
do not treat those as fact.

---

## Section 1 — sky2: Marvell 88E8053 GbE (PCI 11ab:4362)

### 1.1 Where the chip is and how it identifies itself

Verified from a real MacBook2,1 probe (`lspci -vvv`, probe `12cfa4cdb2`, linux-hardware.org):

```
01:00.0 Ethernet controller [0200]: Marvell Technology Group Ltd.
        88E8053 PCI-E Gigabit Ethernet Controller [11ab:4362] (rev 22)
        Subsystem: Marvell Technology Group Ltd. Marvell RDK-8053 [11ab:5321]
        Physical Slot: 0
        Interrupt: pin A routed to IRQ 26
        Region 0: Memory at d0200000 (64-bit, non-prefetchable) [size=16K]
        Region 2: I/O ports at 1000 [size=256]
        Expansion ROM at d0220000 [disabled] [size=128K]
        Capabilities: [5c] MSI: Enable- Count=1/2 Maskable- 64bit+
        Capabilities: [e0] Express (v1) Legacy Endpoint
        Kernel driver in use: sky2
```

- The NIC is a **PCI Express endpoint behind root port `00:1c.0`**, i.e. it is **not on bus 0**.
  On QEMU the e1000 sits directly on bus 0, so **bridge traversal in `kernel/src/pci.rs` is
  exercised only on real hardware** — verify it walks secondary buses before step 2 of the
  milestone plan. [linux-hardware probe 12cfa4cdb2]
- VPD: `Product Name: Marvell Yukon 88E8053 Gigabit Ethernet Controller`,
  `Engineering changes: Rev. 2.2`. PCI revision register reads 0x22 (decimal 22).
  [linux-hardware probe 12cfa4cdb2]
- PCI IDs: Linux matches `11ab:4362` in `sky2_id_table` — `{ PCI_DEVICE(PCI_VENDOR_ID_MARVELL, 0x4362) }, /* 88E8053 */` [sky2.c:120].
- **Chip identification is not done from PCI ID** but from on-chip registers after mapping
  BAR0 (§1.4).

`IRQ 26` above is the ACPI/IO-APIC GSI Linux computes. Our kernel runs on the legacy 8259
only; the 8259 line for this device must come from `PCI_INTERRUPT_LINE` (config 0x3c) or the
ICH7 PIRQ router (config 0x60–0x63 of `00:1f.0`). What value those hold on this machine is
**[unverified]** — one more reason the first driver revision is polled (§1.12).

### 1.2 PCI BAR layout

| BAR | Type | Size (MacBook2,1) | Used by Linux sky2? |
|---|---|---|---|
| BAR0 (+BAR1 as 64-bit upper half) | memory, **64-bit, non-prefetchable** | **16 KB** (`reg 0x10: [mem 0xd0200000-0xd0203fff 64bit]`) | **Yes — the only one.** `hw->regs = ioremap(pci_resource_start(pdev, 0), 0x4000);` [sky2.c:4892] — exactly the 16 KB BAR |
| BAR2 (`reg 0x18`) | I/O, 256 bytes (`0x1000-0x10ff`) | 256 B | No. `pci_request_regions` claims it, the driver never does `inb/outb` on it [sky2.c:4842] |
| Expansion ROM (config 0x30) | prefetchable memory, 128 KB | disabled by firmware | No |

**There is no separate "packet RAM" BAR.** The chip's internal RAM buffer and all FIFOs are
reached *through the BAR0 register window* (RAM-buffer registers at `B16_RAM_REGS = 0x0800`
[sky2.h:724], RAM interface registers `B3_*`, GMAC at `0x2800/0x3800` [sky2.h:1130]).

Compare with our e1000 driver: e1000 uses BAR0 (registers) + BAR1 (flash) and writes
descriptor-ring *base addresses* into device registers (`RDBAL/TDBAL`). sky2 instead gives
the device a **host-memory address through the "prefetch unit" registers** (§1.8) and keeps
everything else (FIFOs, RAM buffer, MAC, PHY) inside one 16 KB register window.

### 1.3 Register space: addressing macros and the registers we need

All accesses are `sky2_read{8,16,32}` / `sky2_write{8,16,32}` at `BAR0 + reg`
[sky2.h:2314-2343]. Bank/offset macros (all from sky2.h):

| Macro | Definition | Line |
|---|---|---|
| `SK_REG(port, reg)` | `((port)<<7) + (reg)` — per-port register bank | [sky2.h:665] |
| `SK_GMAC_REG(port, reg)` | `BASE_GMAC_1 + port*0x1000 + reg` (0x2800 / 0x3800) | [sky2.h:2346] |
| `Q_ADDR(queue, offs)` | `B8_Q_REGS(0x0400) + queue + offs` | [sky2.h:729, 751] |
| `Y2_QADDR(queue, reg)` | `Y2_B8_PREF_REGS(0x0450) + queue + reg` | [sky2.h:767, 782] |
| `RB_ADDR(offs, queue)` | `B16_RAM_REGS(0x0800) + queue + offs` | [sky2.h:724, 818] |
| `RAM_BUFFER(port, reg)` | `reg \| (port << 6)` | [sky2.h:314] |

Key registers (offsets are from sky2.h; line numbers where they are declared):

| Register | Offset | Purpose |
|---|---|---|
| `B0_CTST` | 0x0004 | Control/status: `CS_RST_SET/CLR` (bit0/1) SW reset, `CS_MRST_SET/CLR` master reset, `Y2_ASF_DISABLE` (1<<12), `Y2_LED_STAT_ON` (1<<9) |
| `B0_POWER_CTRL` | 0x0007 | `PC_VAUX_ENA/PC_VCC_ENA/PC_VAUX_OFF/PC_VCC_ON` power mux |
| `B0_ISRC` / `B0_IMSK` | 0x0008 / 0x000C | global interrupt source / mask [sky2.h:260-261] |
| `B0_HWE_ISRC` / `B0_HWE_IMSK` | 0x0010 / 0x0014 | HW-error interrupt source/mask |
| `B0_Y2_SP_ISRC2` | 0x001C | "Special" source; **reading it masks interrupts as a side effect** (Linux: `sky2_intr` comment [sky2.c:3058]) |
| `B0_Y2_SP_EISR` | 0x0024 | Enter-ISR (level) — Linux polls this in `sky2_poll` [sky2.c:3023] |
| `B0_Y2_SP_LISR` | 0x0028 | Leave-ISR — **read to ack** when done processing [sky2.c:3047] |
| `B0_Y2_SP_ICR` | 0x002C | interrupt clear register (Linux writes 2 when source read returns 0/~0) [sky2.c:3061] |
| `B2_MAC_1`..`B2_MAC_3` | 0x0100/0x0108/0x0110 | MAC address bytes (6 bytes at `B2_MAC_1 + port*8`) [sky2.c:4665] |
| `B2_MAC_CFG` | 0x011A | chip revision, bits 7..4 (`CFG_CHIP_R_MSK`), `CFG_SNG_MAC` bit0 |
| `B2_CHIP_ID` | 0x011B | chip id: `CHIP_ID_YUKON_EC = 0xb6` [sky2.h:540] (88E8053 is a Yukon-EC part — **read it, don't assume**) |
| `B2_PMD_TYP` | 0x0119 | PMD type; `'L'/'S'/'P'` ⇒ fibre PHY [sky2.c:3211] |
| `B2_E_0` | 0x011C | internal RAM size in **4 KB blocks** — nonzero ⇒ `SKY2_HW_RAM_BUFFER` [sky2.c:3222] and `ramsize = B2_E_0 * 4` KB [sky2.c:~1675] |
| `B2_Y2_CLK_GATE` / `B2_Y2_HW_RES` | 0x011D / 0x011E | clock gating; `CFG_LINK_1/2_AVAIL` ⇒ port count [sky2.c:3216-3220] |
| `B2_TST_CTRL1` | 0x0158 | `TST_CFG_WRITE_ON` (1<<1) / `TST_CFG_WRITE_OFF` — **must be ON to write PCI config regs through the window** [sky2.c:3259] |
| `Y2_CFG_SPC` | 0x1C00 | window onto the device's PCI config space: `sky2_pci_read/write*(0x1C00 + cfg_off)` [sky2.h:362, 2408-2427]. PCI capability regs used: `PCI_DEV_REG1..5` = cfg 0x40/0x44/0x80/0x84/0x88 [sky2.h:12-17] |
| `TXA_CTRL` etc. | 0x0210 (via `SK_REG`) | TX arbiter: `TXA_ENA_ARB`, `TXA_DIS_FSYNC\|TXA_DIS_ALLOC\|TXA_STOP_RC` |
| queue regs | `Q_ADDR(q, …)` | `Q_DONE` (0x24, 16-bit completed index), `Q_CSR` (0x34, BMU control), `Q_TEST` (0x38), `Q_WM` (0x40, watermark) [sky2.h:729-751] |
| prefetch unit | `Y2_QADDR(q, …)` | `PREF_UNIT_CTRL` 0x00, `PREF_UNIT_LAST_IDX` 0x04, `ADDR_LO/HI` 0x08/0x0C, `GET_IDX` 0x10, `PUT_IDX` 0x14 [sky2.h:767-780] |
| status unit | 0x0E80.. | `STAT_CTRL` 0x0E80 (`SC_STAT_CLR_IRQ` 1<<4), `STAT_LAST_IDX` 0x0E84, `STAT_LIST_ADDR_LO/HI` 0x0E88/0x0E8C, `STAT_PUT_IDX` 0x0E9C [sky2.h:1053-1063] |
| `GMAC_CTRL` / `GPHY_CTRL` | 0x0F00 / 0x0F04 (per port) | MAC/PHY reset: `GMC_RST_SET/CLR`, `GPC_RST_SET/CLR`, read-only status `GPC_LINK` (1<<26) |
| `GMAC_IRQ_SRC` / `GMAC_IRQ_MSK` | 0x0F08 / 0x0F0C (per port) | per-port MAC IRQ source/mask; default mask `GMAC_DEF_MSK = GM_IS_TX_FF_UR \| GM_IS_RX_FF_OR` [sky2.h:2072] |
| `GMAC_LINK_CTRL` | 0x0F10 (per port) | `GMLC_RST_SET/CLR` |
| RX/TX GMAC FIFOs | `RX_GMF_CTRL_T` 0x0C48, `TX_GMF_CTRL_T` 0x0D48 (per port) | FIFO control: `GMF_RST_SET/CLR`, `GMF_OPER_ON`, flush masks, store&forward bits |
| GMAC (per port, via `SK_GMAC_REG`) | see below | |

GMAC register offsets (declared [sky2.h:1631-1669]): `GM_GP_STAT` 0x0000, `GM_GP_CTRL` 0x0004,
`GM_TX_CTRL` 0x0008, `GM_RX_CTRL` 0x000C, `GM_TX_FLOW_CTRL` 0x0010, `GM_TX_PARAM` 0x0014,
`GM_SERIAL_MODE` 0x0018, `GM_SRC_ADDR_1L/2L` 0x001C/0x0028, `GM_MC_ADDR_H1..H4` 0x0034..0x0040,
`GM_TX/RX/TR_IRQ_SRC` 0x0044/0x0048/0x004C, `GM_TX/RX/TR_IRQ_MSK` 0x0050/0x0054/0x0058,
`GM_SMI_CTRL` 0x0080, `GM_SMI_DATA` 0x0084, `GM_PHY_ADDR` 0x0088, MIB counters 0x0100-0x025C.

Useful GMAC bits: `GM_GPCR_RX_ENA` 1<<11, `GM_GPCR_TX_ENA` 1<<12, `GM_GPCR_AU_SPD_DIS/DUP_DIS/FCT_DIS`
1<<0/1<<2/1<<1, `GM_GPSR_LINK_UP` 1<<12 (status) [sky2.h:1729, 1747]; `GM_RXCR_UCF_ENA` 1<<15,
`GM_RXCR_MCF_ENA` 1<<14, `GM_RXCR_CRC_DIS` 1<<13 [sky2.h:1776-1780].

### 1.4 Identification sequence at probe time

Mirror of `sky2_init` [sky2.c:3120-3226], after mapping BAR0:

1. Enable clocks: PCI cfg `PCI_DEV_REG3` (0x80) ← 0 through the window (`sky2_pci_write32`),
   so bad PCI reads don't fake a dead chip [sky2.c:3125].
2. `B0_CTST ← CS_RST_CLR` (clear SW reset) [sky2.c:3127].
3. `chip_id = read8(B2_CHIP_ID)`; `chip_rev = (read8(B2_MAC_CFG) >> 4) & 0xF`
   [sky2.c:3129-3130]. For 88E8053 expect `CHIP_ID_YUKON_EC (0xb6)` →
   `hw->flags = SKY2_HW_GIGABIT | SKY2_HW_RSS_BROKEN` [sky2.c:3157-3163] —
   i.e. **gigabit copper, no RSS, no `SKY2_HW_NEW_LE`, no auto-TX-checksum** — this decides
   which descriptor flavour we must use (§1.7).
4. `pmd_type = read8(B2_PMD_TYP)`; `'L'/'S'/'P'` ⇒ fibre [sky2.c:3211-3213]. On a copper
   MacBook NIC it should be neither → copper path.
5. Port count: `B2_Y2_HW_RES & CFG_DUAL_MAC_MSK == both` and `B2_Y2_CLK_GATE` bit
   `Y2_STATUS_LNK2_INAC` clear ⇒ 2 ports [sky2.c:3216-3220]. 88E8053 is single-port — expect 1.
6. `B2_E_0 != 0` ⇒ set `SKY2_HW_RAM_BUFFER` [sky2.c:3222-3223]. **Read it; don't assume.**
7. MAC address: `memcpy` 6 bytes from `B2_MAC_1 + port*8` [sky2.c:4665]; if not unicast,
   fall back to a locally-administered address [sky2.c:4670-4678].

### 1.5 Init sequence outline (reset → MAC/PHY → FIFOs → rings → start)

Order and content follow `sky2_reset` [sky2.c:3228-3421] and `sky2_hw_up` [sky2.c:1646-1710],
which is `sky2_open`'s work [sky2.c:1734-1773]:

1. **Chip reset / housekeeping** (`sky2_reset`):
   - ASF off: `B0_CTST ← Y2_ASF_DISABLE`; for non-EX/Supreme chips
     `B28_Y2_ASF_STAT_CMD ← Y2_ASF_RESET` first [sky2.c:3235-3252].
   - SW reset: `B0_CTST ← CS_RST_SET` then `CS_RST_CLR` [sky2.c:3255-3256].
   - `B2_TST_CTRL1 ← TST_CFG_WRITE_ON`; read/ack PCI status errors via the window;
     `B0_CTST ← CS_MRST_CLR` [sky2.c:3259-3266].
   - `sky2_power_on` [sky2.c:~150]: `B0_POWER_CTRL ← PC_VAUX_ENA|PC_VCC_ENA|PC_VAUX_OFF|PC_VCC_ON`,
     `B2_Y2_CLK_CTRL ← Y2_CLK_DIV_DIS`, `B2_Y2_CLK_GATE ← 0`, `B0_CTST ← Y2_LED_STAT_ON`
     (the `SKY2_HW_ADV_POWER_CTL` block does not apply to plain Yukon-EC — skip it).
   - Per port: `GMAC_LINK_CTRL ← GMLC_RST_SET` then `GMLC_RST_CLR` [sky2.c:3282-3284].
   - Quiesce: `B2_TI_CTRL ← TIM_STOP, TIM_CLR_IRQ`; `B28_DPT_CTRL ← DPT_STOP`
     (descriptor-poll timer **off**); `GMAC_TI_ST_CTRL ← GMT_ST_STOP|GMT_ST_CLR_IRQ`
     (timestamp timer off) [sky2.c:3349-3361].
   - `SK_REG(port, TXA_CTRL) ← TXA_ENA_ARB` per port [sky2.c:3363-3365].
   - RAM interface: `RAM_BUFFER(port, B3_RI_CTRL) ← RI_RST_CLR` and all
     `B3_RI_WTO_*/B3_RI_RTO_* ← SK_RI_TO_53 (=36)` [sky2.c:3367-3383].
   - `B0_HWE_IMSK ← Y2_HWE_ALL_MASK`; `sky2_gmac_reset` per port (mask all GMAC IRQs, clear
     MC hash, `GM_RX_CTRL |= UCF_ENA|MCF_ENA`) [sky2.c:284-298, 3387-3388].
   - **Status unit**: `STAT_CTRL ← SC_STAT_RST_SET` then `CLR`; `STAT_LIST_ADDR_LO/HI ←`
     status-ring DMA address; `STAT_LAST_IDX ← st_size-1`; `STAT_TX_IDX_TH ← 10`;
     `STAT_FIFO_WM ← 16`; `STAT_FIFO_ISR_WM ← 16`; timers
     `STAT_TX_TIMER_INI ← 1000µs·125MHz`, `STAT_ISR_TIMER_INI ← 20µs·clk`,
     `STAT_LEV_TIMER_INI ← 100µs·clk` (`sky2_mhz()` returns 125 for Yukon-EC
     [sky2.c:3085-3093]); `STAT_CTRL ← SC_STAT_OP_ON`; start the three timers
     (`TIM_START`) [sky2.c:3390-3420].
2. **`sky2_mac_init(port)`** [sky2.c:898-1035]:
   - `GPHY_CTRL ← GPC_RST_SET` then `GPC_RST_CLR`; `GMAC_CTRL ← GMC_RST_CLR`;
     read `GMAC_IRQ_SRC` once to clear stale sources;
     `GMAC_IRQ_MSK ← GMAC_DEF_MSK` [sky2.c:902-921].
   - `sky2_phy_power_up` [sky2.c:696-716]: `B2_TST_CTRL1 ← TST_CFG_WRITE_ON`, clear
     `PCI_Y2_PHY1_POWD` (1<<26) in PCI cfg `PCI_DEV_REG1`, `TST_CFG_WRITE_OFF`.
     (The `GPC_RST_CLR` branch only runs for `SKY2_HW_ADV_POWER_CTL` chips, not plain EC.)
   - `sky2_phy_init(port)` — §1.6 [sky2.c:326-690, called at 932].
   - MIB clear: `GM_PHY_ADDR |= GM_PAR_MIB_CLR`, read counters `GM_MIB_CNT_BASE..END`,
     restore [sky2.c:935-941].
   - TX params: `GM_TX_CTRL ← TX_COL_THR(4)`; `GM_RX_CTRL ← UCF_ENA|CRC_DIS|MCF_ENA`
     (strip CRC, pass unicast+multicast); `GM_TX_FLOW_CTRL ← 0xffff`;
     `GM_TX_PARAM ←` defaults (jam len 3, jam IPG 0x0b, IPG/jam 0x1c, backoff 4);
     `GM_SERIAL_MODE ← DATA_BLIND(4)|GM_SMOD_VLAN_ENA|IPG_DATA_VAL(0x1e)` (jumbo bit only
     if MTU > 1500); MAC addresses into `GM_SRC_ADDR_2L` (data) and `GM_SRC_ADDR_1L`
     (pause) [sky2.c:944-986].
   - Zero `GM_TX/RX/TR_IRQ_MSK` (ignore MIB overflows) [sky2.c:988-991].
   - **RX MAC FIFO**: `RX_GMF_CTRL_T ← GMF_RST_CLR`, then `GMF_OPER_ON|GMF_RX_F_FL_ON`
     (plus `GMF_RX_OVER_ON` only on EX/FE+); `RX_GMF_FL_MSK ← GMR_FS_ANY_ERR` (flush on any
     error — on Yukon-XL it must be 0, "Hardware errata" [sky2.c:967-973]);
     `RX_GMF_FL_THR ← RX_GMF_FL_THR_DEF(0xa) + 1` — the `+1` is a **"magic mystery
     workaround … pause bug"** [sky2.c:1000-1006].
   - **TX MAC FIFO**: `TX_GMF_CTRL_T ← GMF_RST_CLR`, then `GMF_OPER_ON`
     [sky2.c:1010-1012]. If the chip has **no** RAM buffer (`!(SKY2_HW_RAM_BUFFER)`), also
     set pause thresholds and `sky2_set_tx_stfwd` (store&forward) [sky2.c:1014-1024].
3. **RAM buffer partition** (only if `B2_E_0 != 0`): `sky2_ramset` rx-queue = first ~⅔,
   tx-queue = rest; RX thresholds `RB_RX_UTHP = ¾`, `RB_RX_LTHP = ½`, `RB_RX_UTPP = space−8K/8`,
   `RB_RX_LTPP = ¼`; TX queues get `RB_ENA_STFWD`; finally `RB_ENA_OP_MD`
   [sky2.c:1037-1075, 1680-1688]. Also reset the *sync* TX queue (`Q_XS1/Q_XS2`) — unused
   [sky2.c:1692-1694].
4. **`sky2_qset(txq)`** [sky2.c:1077-1084]: `Q_CSR ← BMU_CLR_RESET`, then `BMU_OPER_INIT`
   (= `BMU_CLR_IRQ_PAR|BMU_CLR_IRQ_CHK|BMU_START|BMU_FIFO_ENA|BMU_OP_ON` [sky2.h:887]),
   then `BMU_FIFO_OP_ON`, then `Q_WM ← BMU_WM_DEFAULT (0x600)`.
5. **`sky2_prefetch_init(q, ring_dma, last)`** [sky2.c:1089-1103]: `PREF_UNIT_RST_SET`
   → `PREF_UNIT_RST_CLR` → `ADDR_HI/LO ← ring DMA address` → `LAST_IDX ← ring_len−1` →
   `PREF_UNIT_OP_ON`, followed by a read-back (write barrier).
6. **RX start (`sky2_rx_start`)** [sky2.c:1518-1596]:
   - `sky2_qset(rxq)`; on PCIe lower the watermark (`Q_WM ← BMU_WM_PEX (0x80)`) [sky2.c:1527-1529].
   - `sky2_prefetch_init(rxq, rx_le_dma, RX_LE_SIZE−1)` — RX ring is **1024 list elements**
     (`RX_LE_SIZE`, `RX_MAX_PENDING = 1024/6 − 2`) [sky2.c:33-37].
   - Fill the RX LEs (§1.7), then `sky2_put_idx(rxq, rx_put)` — `wmb()` then
     `PREF_UNIT_PUT_IDX ← index` [sky2.c:1126-1131].
   - Oversize truncation: `RX_GMF_TR_THR ← (roundup(mtu+18,8) − 8)/4` (≤ 9 bits, 0x1FF),
     `RX_GMF_CTRL_T ← RX_TRUNC_ON` — **"The receiver hangs if it receives frames larger than
     the packet buffer"** [sky2.c:1554-1571].
7. **TX start** happens per packet: `sky2_xmit_frame` builds LEs and ends with
   `sky2_put_idx(hw, txq, tx_prod)` [sky2.c:1823-1987, 1971]. `tx_init` (called from
   `sky2_hw_up` [sky2.c:1655]) seeds the ring with one `OP_ADDR64 | HW_OWNER` LE [sky2.c:~1108-1117].

### 1.6 PHY access (SMI) and PHY init

The 88E8053's copper PHY is reached indirectly through the GMAC's Serial Management
Interface. PHY device address is `PHY_ADDR_MARV = 0` [sky2.h:815]; the register set is the
Marvell 88E1111-compatible one (`PHY_MARV_ID1_C2 = 0x0CC2 /* Yukon-EC (PHY 88E1111) */
[sky2.h:1249]). Whether the PHY silicon is integrated in the 88E8053 (Marvell calls it an
integrated GPHY) or a companion die **does not matter to software — only the SMI path exists**
[unverified as to silicon, verified as to software path].

**SMI read/write protocol** (`gm_phy_read`/`gm_phy_write` [sky2.c:152-206]):

- Write: `GM_SMI_DATA ← value`; `GM_SMI_CTRL ← GM_SMI_CT_PHY_AD(0) | GM_SMI_CT_REG_AD(reg)`
  (write op = bit5 clear); poll `GM_SMI_CTRL` until `GM_SMI_CT_BUSY` (1<<3) clears —
  1000 retries × 10 µs (`PHY_RETRIES`) [sky2.c:40-54].
- Read: `GM_SMI_CTRL ← PHY_AD | REG_AD | GM_SMI_CT_OP_RD` (1<<5); poll until
  `GM_SMI_CT_RD_VAL` (1<<4) sets; then `GM_SMI_DATA` holds the value [sky2.c:56-84].
- `GM_SMI_CTRL` bits: PHY addr 15..11, reg addr 10..6, OP_RD 1<<5, RD_VAL 1<<4, BUSY 1<<3
  [sky2.h:1820-1830].

**PHY init for copper autonegotiation** (`sky2_phy_init` [sky2.c:326-690], the parts that
apply to Yukon-EC copper):

1. `PHY_MARV_EXT_CTRL` (0x14): MAC interface clock = 25 MHz, downshift counters — the
   `SKY2_FLAG_AUTO_SPEED && !SKY2_HW_NEWER_PHY` branch [sky2.c:331-349].
2. `PHY_MARV_PHY_CTRL` (0x10): clear energy-detect (`PHY_M_PC_EN_DET_MSK`), enable automatic
   MDI/MDI-X crossover (`PHY_M_PC_MDI_XMODE(PHY_M_PC_ENA_AUTO)` = 3<<5) — the gigabit-copper
   branch [sky2.c:365-377].
3. Build advertisement: `ct1000 = PHY_M_1000C_AFD|PHY_M_1000C_AHD` (if advertising 1000),
   `adv = PHY_AN_CSMA | PHY_M_AN_100_FD|100_HD|10_FD|10_HD`; flow control via
   `copper_fc_adv[]` (`PHY_M_AN_PC`/`PHY_M_AN_ASP`) [sky2.c:411-470].
4. `ctrl = PHY_CT_RESET | PHY_CT_ANE | PHY_CT_RE_CFG` — the reset bit self-clears and the
   `RE_CFG` bit restarts autonegotiation. Writes: `GM_GP_CTRL ← reg` (auto-update flow
   control left enabled), `PHY_MARV_1000T_CTRL (0x09) ← ct1000`,
   `PHY_MARV_AUNE_ADV (0x04) ← adv`, `PHY_MARV_CTRL (0x00) ← ctrl`
   [sky2.c:455-470].
   Key PHY control bits: `PHY_CT_ANE` 1<<12, `PHY_CT_RE_CFG` 1<<9, `PHY_CT_RESET` 1<<15,
   `PHY_CT_PDOWN` 1<<11 [sky2.h:1174-1186].
5. LEDs (`PHY_MARV_LED_CTRL` 0x18 / `PHY_MARV_LED_OVER` 0x19) — cosmetic; a minimal driver
   may skip [sky2.c:604-623].
6. Enable PHY interrupt on "autonegotiation complete": `PHY_MARV_INT_MASK (0x12) ←
   PHY_M_IS_AN_COMPL` (1<<11) if auto speed, else `PHY_M_DEF_MSK`
   (`LSP_CHANGE|LST_CHANGE|DUP_CHANGE`) [sky2.c:677-682].

### 1.7 Descriptor formats — sky2 list elements vs e1000

sky2 does **not** use e1000-style descriptors. It uses 8-byte **list elements (LEs)** in three
rings (TX, RX, status) — "64 bit command blocks … organized into three (receive, transmit,
status) different rings" [sky2.c:39-42].

**TX LE** [sky2.h:2164-2169] and **RX LE** [sky2.h:2171-2176] have the same layout:

| field | type | meaning |
|---|---|---|
| `addr` | u32 LE | low 32 bits of host address (high bits carried by a separate `OP_ADDR64` LE) |
| `length` | u16 LE | byte count (TX: fragment/packet length; RX: buffer length) |
| `ctrl` | u8 | TX flags: `UDPTCP` 1<<0, `CALSUM` 1<<1, `WR_SUM` 1<<2, `INIT_SUM` 1<<3, `LOCK_SUM` 1<<4, `INS_VLAN` 1<<5, **`EOP` 1<<7** (end of packet) [sky2.h:2104-2112] |
| `opcode` | u8 | operation + **ownership: `HW_OWNER = 1<<7`** [sky2.h:2115] |

Opcode values we need [sky2.h:2116-2149]: `OP_ADDR64 = 0x21` (load upper address bits),
`OP_PACKET = 0x41` (TX packet fragment / RX buffer-to-fill — note RX uses `OP_PACKET` for the
data buffer and `OP_BUFFER = 0x40` for extra fragments [sky2.c:1186-1197]).
Offload opcodes we will **not** use: `OP_TCP*` checksum (0x11/0x12/0x14/0x18), `OP_VLAN` 0x22,
`OP_LRGLEN` 0x24 / `OP_MSS` 0x28 (TSO), `OP_LARGESEND` 0x43, `OP_LSOV2` 0x45.

**Status LE** [sky2.h:2178-2183]: `{ status: u32, length: u16, css: u8, opcode: u8 }`.

- RX packet status: `OP_RXSTAT = 0x60` [sky2.h:2140]; frame length in `status` bits 30..16
  (`GMR_FS_LEN`) [sky2.h:1840]; error summary `GMR_FS_ANY_ERR` (jabor/long/frag/CRC/MII/…)
  [sky2.h:1856-1859]; `GMR_FS_RX_OK` 1<<8; port number in `css` bit0 (`CSS_LINK_BIT`)
  [sky2.h:2160].
- TX completion: `OP_TXINDEXLE = 0x68` [sky2.h:2147]; for port 0 the completed TX index is
  `status & 0xfff`, port 1 uses `((status>>24)&0xff) | ((length&0xf)<<8)`
  [sky2.c:2777-2784].
- Checksum/VLAN status opcodes (`OP_RXCHKS` 0x64, `OP_RXVLAN` 0x62, `OP_RSS_HASH` 0x65) —
  skip; with `!SKY2_HW_NEW_LE` chips Linux also programs an `OP_TCPSTART` LE and
  `BMU_ENA/DIS_RX_CHKSUM` in `Q_CSR` [sky2.c:1150-1164] — **leave checksum disabled**
  (`BMU_DIS_RX_CHKSUM` path or simply never write `BMU_ENA_RX_CHKSUM`).

**Ownership model.** Driver-owned ⇒ `opcode & HW_OWNER` set (bit 7); hardware clears it when
done. For TX, the driver does not scan TX LEs for completion — it uses the **status ring**
(or `Q_DONE`). For RX, completion is *only* reported via status LEs (length/error), the RX LE
itself is just "here is a buffer".

**e1000 vs sky2 (what changes vs our current driver):**

| | e1000 (current) | sky2 (new) |
|---|---|---|
| descriptor size | 16 B RX / 16 B TX | **8 B** list elements |
| ownership | status `DD` bit (RX desc.0 / TX desc.0) | `HW_OWNER` (bit7 of `opcode`) |
| ring base/len | `RDBAL/RDBH/RDLEN`, `RDT` (tail) | `PREF_UNIT_ADDR_LO/HI`, `PREF_UNIT_LAST_IDX`, `PREF_UNIT_PUT_IDX` |
| completion | descriptor bits + `ICR` | **third status ring** (`STAT_LIST_ADDR_*`, `STAT_PUT_IDX`) or `Q_DONE` |
| checksum/VLAN flags | per-descriptor `POPTS`/`DEXT` | `ctrl` byte opcodes — not used initially |

### 1.8 Starting TX/RX: queue select, ring pointers

- **Queue bases** (`queue select` constants) [sky2.h:805-810]:
  `Q_R1 = 0x0000` (RX port1), `Q_R2 = 0x0080`, `Q_XS1 = 0x0200` (sync TX — unused),
  `Q_XA1 = 0x0280` (async TX port1), `Q_XS2/Q_XA2` for port 2. Linux tables:
  `txqaddr[] = { Q_XA1, Q_XA2 }`, `rxqaddr[] = { Q_R1, Q_R2 }` [sky2.c:110-112].
  All queue-register accesses go through `Q_ADDR(q, …)`; prefetch-unit accesses through
  `Y2_QADDR(q, …)`.
- **Ring programming**: no "base/length" register pair like e1000's RDBAL/RDLEN —
  the *address* goes to `Y2_QADDR(q, PREF_UNIT_ADDR_LO/HI)`, the *length−1* to
  `PREF_UNIT_LAST_IDX`, and the *producer index* to `PREF_UNIT_PUT_IDX`
  (§1.5 step 5, `sky2_prefetch_init` [sky2.c:1089-1103]).
  The hardware's consumed position is `PREF_UNIT_GET_IDX` (read-only) [sky2.h:775].
- **Kick TX**: `wmb()` then `PREF_UNIT_PUT_IDX ← tx_prod` (`sky2_put_idx`
  [sky2.c:1126-1131], used at [sky2.c:1971]). One write starts/continues DMA fetching;
  there is no separate "start" bit per packet.
- **Kick RX**: same mechanism, `PREF_UNIT_PUT_IDX ← rx_put` after submitting RX LEs
  (`sky2_rx_update` [sky2.c:1480-1483]).
- **BMU control** (`Q_CSR`): start/stop sequences used by Linux —
  reset: `BMU_RST_SET|BMU_FIFO_RST`; init: `BMU_CLR_RESET` → `BMU_OPER_INIT` →
  `BMU_FIFO_OP_ON`; stop RX: first `RB_ADDR(rxq, RB_CTRL) ← RB_DIS_OP_MD` (RAM buffer off),
  poll `Q_RSL == Q_RL` (shadow/level equal ⇒ DMA drained — **"the RX Stop command will not
  work for Yukon-2 if the BMU does not reach the end of packet"**, sky2.c:1313-1341), *then*
  `Q_CSR ← BMU_RST_SET|BMU_FIFO_RST`, then `PREF_UNIT_RST_SET` [sky2.c:1324-1341].
  For TX stop: `Q_CSR ← BMU_STOP` [sky2.c:2073].
- **TX arbiter** must be enabled (`SK_REG(port, TXA_CTRL) ← TXA_ENA_ARB` [sky2.c:3365]) —
  already part of `sky2_reset`.

### 1.9 Completion and interrupt registers (we start polled, this is for later)

Interrupt plumbing, as used by Linux:

- **Top level**: mask = `B0_IMSK` (0x000C); sources = `B0_ISRC` (0x0008). Base enable value
  `Y2_IS_BASE = Y2_IS_HW_ERR | Y2_IS_STAT_BMU` [sky2.h:438], plus per-port
  `Y2_IS_PORT_1 = IRQ_PHY1|IRQ_MAC1|CHK_TXA1|CHK_RX1` [sky2.h:434] (`portirq_msk[]`
  [sky2.c:113]). Enable in `sky2_open`: `B0_IMSK |= portirq_msk[port]` [sky2.c:1754-1764];
  `sky2_setup_irq` initially writes `Y2_IS_BASE` [sky2.c:1711-1731].
- **ISR entry**: `sky2_intr` reads `B0_Y2_SP_ISRC2` — **"Reading this mask interrupts as
  side effect"** [sky2.c:3053-3070]; if 0/`~0` it writes `B0_Y2_SP_ICR ← 2` and bails.
  NAPI then reads `B0_Y2_SP_EISR` (level) in `sky2_poll` [sky2.c:3020-3051] and, when done,
  **reads `B0_Y2_SP_LISR`** to leave the ISR [sky2.c:3047].
- **Status-ring IRQ ack**: after draining status entries, `STAT_CTRL ← SC_STAT_CLR_IRQ`
  (1<<4) [sky2.c:2793].
- **Per-port MAC IRQ**: `SK_REG(port, GMAC_IRQ_SRC)` (read), `GMAC_IRQ_MSK` (write);
  sources `GM_IS_TX_FF_UR` 1<<3, `GM_IS_RX_FF_OR` 1<<1, `GM_IS_RX_COMPL` 1<<0 …
  [sky2.h:2064-2073]; ack via `RX_GMF_CTRL_T ← GMF_CLI_RX_FO` / `TX_GMF_CTRL_T ← GMF_CLI_TX_FU`
  [sky2.c:2903-2911].
- **PHY IRQ**: `Y2_IS_IRQ_PHY1` → read `PHY_MARV_INT_STAT` (0x13) + `PHY_MARV_PHY_STAT`
  (0x11) [sky2.c:2296-2334].
- **HW errors**: `B0_HWE_ISRC/B0_HWE_IMSK`; ack bits like `RI_CLR_RD_PERR/RI_CLR_WR_PERR`
  (RAM parity), `BMU_CLR_IRQ_PAR`, `BMU_CLR_IRQ_TCP` [sky2.c:2802-2887].
- MSI exists on this chip (`Capabilities: [5c] MSI`) and Linux tests it with a software-forced
  IRQ (`CS_ST_SW_IRQ`, `Y2_IS_IRQ_SW`) and has a DMI blacklist [sky2.c:4691-4745, 4772-4809].
  **We skip MSI entirely**; polled first, INTx later if needed.

**[unverified]** Linux drives status completion from timers + interrupts; whether
`STAT_PUT_IDX` advances correctly with `B0_IMSK = 0` (pure polling) is expected to work —
the status unit is enabled unconditionally in `sky2_reset` — but this must be confirmed on
hardware in milestone step 7.

### 1.10 Link setup: autonegotiation control, status, polling vs interrupts

- **Control**: `sky2_phy_init` advertises and restarts AN (§1.6 step 3-4). Forced-speed
  mode instead: `ctrl |= PHY_CT_SP1000/SP100` and `GM_GP_CTRL` gets
  `GM_GPCR_AU_DUP_DIS|AU_SPD_DIS` plus `GM_GPCR_SPEED_1000/100/DUP_FULL`
  [sky2.c:430-454].
- **Result registers** (`sky2_autoneg_done` [sky2.c:2233-2293]):
  `PHY_MARV_AUNE_ADV` (0x04) / `PHY_MARV_AUNE_LP` (0x05) for flow control;
  `PHY_MARV_PHY_STAT` (0x11) for the result: **`PHY_M_PS_SPDUP_RES` 1<<11 (speed/duplex
  resolved)**, `PHY_M_PS_FULL_DUP` 1<<13, speed in bits 15..14
  (`PHY_M_PS_SPEED_1000 = 1<<15`, `PHY_M_PS_SPEED_100 = 1<<14`) [sky2.h:1355-1372];
  `PHY_M_PS_LINK_UP` 1<<10 = link good. Speed decode helper `sky2_phy_speed`
  [sky2.c:2149-2169].
- **Link up actions** (`sky2_link_up` [sky2.c:2171-2201]): set IPG for the speed
  (`sky2_set_ipg`, `GM_SERIAL_MODE` IPG 0x1e at 1 Gb, 0x18 otherwise [sky2.c:773-785]),
  `GM_GP_CTRL |= GM_GPCR_RX_ENA|GM_GPCR_TX_ENA` (`sky2_enable_rx_tx` [sky2.c:787-794]),
  `PHY_MARV_INT_MASK ← PHY_M_DEF_MSK`, link LED on.
- **Link down** (`sky2_link_down` [sky2.c:2203-2223]): PHY int mask 0, clear
  `GM_GPCR_RX_ENA|TX_ENA`, LED off, re-run `sky2_phy_init`.
- **Interrupt-driven path**: PHY IRQ (`Y2_IS_IRQ_PHY1`) → `sky2_phy_intr` →
  `PHY_M_IS_AN_COMPL` (1<<11) / `PHY_M_IS_LST_CHANGE` (1<<10) / `PHY_M_IS_LSP_CHANGE`
  (1<<14) / `PHY_M_IS_DUP_CHANGE` (1<<13) [sky2.h:1383-1403] → link up/down.
- **Polled path (what we want first)**: read `PHY_MARV_PHY_STAT & PHY_M_PS_LINK_UP`, or the
  MAC-side `GM_GP_CTRL`/`GM_GP_STAT` bit `GM_GPSR_LINK_UP` 1<<12 [sky2.h:1729], or
  `GPHY_CTRL` `GPC_LINK` 1<<26 [sky2.h:2039]. Poll every PIT tick; on 0→1 transition run the
  `sky2_link_up` steps; on 1→0 run `sky2_link_down` steps.

### 1.11 Known quirks / errata relevant to 88E8053

All quoted comments are from Linux sky2.c:

1. **Yukon-EC rev A1 unsupported**: "This rev is really old, and requires untested
   workarounds" → probe rejects `CHIP_REV_YU_EC_A1` [sky2.c:3157-3161]. Check `chip_rev`
   (from `B2_MAC_CFG`) at probe; expect A2/A3 on a 2007 part (rev 2.2 per VPD — that is the
   *PCI* revision, not the MAC rev; don't confuse them).
2. **RSS is broken on Yukon-EC** (`SKY2_HW_RSS_BROKEN`) [sky2.c:3163] — skip RSS/hash.
3. **RX truncation hang**: "The receiver hangs if it receives frames larger than the packet
   buffer" — must program `RX_GMF_TR_THR` + `RX_TRUNC_ON` [sky2.c:1554-1571].
4. **RX FIFO alignment hang**: "Workaround for a bug in FIFO that cause hang if the FIFO if
   the receive buffer is not 64 byte aligned" — Linux aligns RX data to **8 bytes**
   (`PTR_ALIGN(skb->data, 8)`) [sky2.c:1455-1464]. Keep RX buffers ≥8-byte aligned.
5. **RX stop ordering**: RAM buffer first, poll `Q_RSL == Q_RL`, then reset BMU (§1.8)
   [sky2.c:1313-1341].
6. **Pause-flush threshold +1**: `RX_GMF_FL_THR_DEF + 1`, "Another magic mystery workaround
   from sk98lin" [sky2.c:1000-1006].
7. **Bogus RX status on some chips** (FE+ A0): "This chip has hardware problems that
   generates bogus status. So do only marginal checking…" [sky2.c:2573-2580] — not EC, but
   keep our status checking simple: trust `GMR_FS_RX_OK` + length match, drop the rest.
8. **TSO/csum pitfalls — simply not enabled**: TX checksum encoding differs per chip
   (`SKY2_HW_AUTO_TX_SUM` only on Yukon-EX non-B0 [sky2.c:3152-3154]); old-LE chips need an
   extra `OP_TCPLISW` LE with start/write offsets [sky2.c:1893-1919]; RX checksum validity is
   inferred by comparing two 16-bit halves of `status` and *disables itself* on mismatch
   [sky2.c:2656-2683]. Our plan: **never enable** `BMU_ENA_RX_CHKSUM`, never emit
   `OP_TCP*/CALSUM` LEs — software checksums in the stack.
9. **VLAN**: `GM_SMOD_VLAN_ENA` is set in `GM_SERIAL_MODE` regardless [sky2.c:973]; hardware
   VLAN *stripping/tagging* (`RX_VLAN_STRIP_ON`, `TX_VLAN_TAG_ON`) stays off [sky2.c:1409-1430].
   Frames will carry their 4-byte tag — fine, our stack can ignore/drop VLAN frames initially.
10. **Jumbo**: skip — keep MTU 1500 (`GM_SMOD_JUMBO_ENA` off, `RX_GMF_TR_THR` small).
11. **WOL/ASF/power management**: `sky2_wol_init`, `sky2_power_aux`, suspend/resume — skip.
    Only `sky2_power_on` (§1.5) is needed at boot.
12. **Dual-port PCI-X split-transaction workaround** [sky2.c:1658-1668] — PCIe single-port
    MacBook: not applicable.
13. **ASPM**: Linux notes "disabling ASPM on pre-1.1 PCIe device" for this exact MacBook
    [linux-hardware dmesg probe d8b686d7fe]. GRUB/firmware may leave ASPM on; consider
    clearing `LnkCtl` ASPM bits or at least being aware if the link stalls. **[unverified]**
    whether it matters without PCIe ASPM handling in our OS (we likely never enable it).

### 1.12 What the minimal polled driver skips

- **No interrupts**: leave `B0_IMSK = 0`, `B0_HWE_IMSK` can stay at reset value or
  `Y2_HWE_ALL_MASK` (sources are harmless while masked). Poll `STAT_PUT_IDX` for RX/TX
  completion; poll `PHY_MARV_PHY_STAT` for link. (Also sidesteps the unknown PIRQ routing,
  §1.1.)
- **No offloads**: no TX/RX checksum LEs, no TSO (`OP_LARGESEND/OP_MSS/OP_LRGLEN`), no RSS,
  no IP-ID auto-increment (`BMU_TX_IPIDINCR`), no home/routing-header checksum fix.
- **No VLAN offload**, no jumbo, no flow control (advertise pause=0: `copper_fc_adv[FC_NONE]`
  — or just accept whatever AN negotiates and ignore pause frames).
- **No WOL, no ASF, no power management, no MIB/statistics, no ethtool equivalents**,
  no MSI, no second port, no sync TX queue (`Q_XS*`), no pattern RAM.
- **No EEPROM/VPD reading** (MAC comes from `B2_MAC_1`, which the Apple EFI has programmed).

### 1.13 Milestone plan — sky2 driver

**Testing reality: QEMU cannot emulate this chip.** QEMU's `hw/net` provides e1000/e1000e,
rtl8139, ne2k, pcnet, virtio-net, vmxnet3, tulip, sungem, etc. — there is **no Marvell
Yukon/88E8053 device model** (checked QEMU `hw/net/meson.build` and the QEMU NIC list in the
manpage; the only QEMU "sky2" references are an iPXE ROM patch). Therefore:

- **QEMU can only test the shared plumbing** (PCI scan/BAR mapping code paths, serial-marker
  discipline, ring/DMA bookkeeping logic reviewed against e1000 behaviour).
- **All sky2 register sequences must be validated on the real MacBook**, booting the ISO via
  Option/C DVD (`AGENTS.md`).

Ordered steps:

1. **[QEMU]** Extend `pci.rs` constants with `11ab:4362`; make the enumerator walk PCI-bridge
   secondary buses (QEMU's e1000 on bus 0 won't exercise this — add a QEMU test that at least
   enumerates the e1000 through the same code and prints vendor/device/BAR0 as a serial
   marker). Test: `cargo xtask smoke` still passes.
2. **[Real HW]** *Identify:* find `11ab:4362` at `01:00.0` (behind bridge `00:1c.0`); read
   BAR0 as a **64-bit** BAR (two config dwords); set IO/MEM/BusMaster in `PCI_COMMAND`
   (Linux does `pci_enable_device` + `pci_set_master` [sky2.c:4819, 4848]); map 16 KB.
   Print `B2_CHIP_ID`, `B2_MAC_CFG` rev, `B2_Y2_HW_RES`, `B2_E_0`, MAC from `B2_MAC_1`.
   Fail loudly if `B2_CHIP_ID` reads `0xFF`/`0xFFFF` (bad map).
3. **[Real HW]** *Reset + power:* the `sky2_reset` subset of §1.5 step 1 (SW reset, clock
   power-on, timer/DP-timer off, TX arbiter on, RAM-interface timeouts, GMAC reset, status
   unit with a static status ring). Verify reads are stable afterwards (re-read chip id).
4. **[Real HW]** *MAC/PHY init:* `sky2_mac_init` + `sky2_phy_init` subset (§1.5 step 2,
   §1.6), including `sky2_phy_power_up`. Verify SMI works by reading `PHY_MARV_ID0/ID1`
   (expect `0x0141` + an 88E1111-class ID1, e.g. `0x0CC2` [sky2.h:1243-1250]).
5. **[Real HW]** *Link:* poll `PHY_MARV_PHY_STAT` until `PHY_M_PS_LINK_UP|PHY_M_PS_SPDUP_RES`;
   print negotiated speed/duplex; then run the `sky2_link_up` steps (`set_ipg`, enable
   `GM_GPCR_RX_ENA|TX_ENA`).
6. **[Real HW]** *Rings:* allocate aligned static buffers for status ring (e.g. 64 entries),
   TX LE ring (power of two, 128), RX LE ring (1024 LEs) + RX packet buffers (8-byte
   aligned, ≥1600 B each); program `sky2_qset`, `sky2_prefetch_init`, RAM-buffer split if
   `B2_E_0 != 0`, `sky2_rx_start` with truncation threshold.
7. **[Real HW]** *TX smoke:* transmit a fixed ARP request / DHCP discover (reuse the e1000
   test frame); confirm `Q_DONE` advances or an `OP_TXINDEXLE` status LE appears; print a
   `SKY2_TX_OK` serial marker.
8. **[Real HW]** *RX smoke:* with a cable attached to a live network, poll `STAT_PUT_IDX`,
   parse `OP_RXSTAT` entries, verify `GMR_FS_RX_OK` + length match, then DHCP (our DHCP
   client already exists). Print `SKY2_RX_OK` / `SKY2_DHCP_OK`.
9. **[Real HW]** *Loop the polled main loop:* link-state polling + RX polling on the PIT tick
   or in the shell loop; soak-test (minutes) for the hangs listed in §1.11 (watchdog-style
   re-check of `Q_RP`/`RX_GMF_RP` like `sky2_rx_hung` [sky2.c:2927-2958] is a cheap addition).
10. **[Real HW, later]** INTx interrupts: resolve the actual 8259 line (config 0x3c / ICH7
    PIRQ router), unmask it in the master PIC, implement the ISR (read `B0_Y2_SP_ISRC2`,
    drain status ring, `B0_Y2_SP_LISR` ack, EOI). Keep polling as fallback.

---

## Section 2 — Keyboard: i8042/PS/2 first, the MacBook reality, USB HID later

### 2.1 Verified hardware facts about the MacBook2,1 keyboard

Everything in this subsection is taken from linux-hardware.org probes of **Apple MacBook2,1**
units (same model as our target):

- **The built-in keyboard is a USB device, not PS/2.** Linux dmesg (probe `d8b686d7fe`):
  `[1.767429] usb 2-2: new full-speed USB device number 2 using uhci_hcd` →
  `[1.960444] usb 2-2: New USB device found, idVendor=05ac, idProduct=021b` →
  `[1.960460] usb 2-2: Product: Apple Internal Keyboard / Trackpad`.
  `input_devices` (probe `12cfa4cdb2`): `Bus=0003 Vendor=05ac Product=021a …
  Phys=usb-0000:00:1d.0-2/input0` — i.e. **Apple VID `05ac`, PID `021a` (ANSI) / `021b`
  (ISO), attached to UHCI controller `00:1d.0`, port 2, full-speed (12 Mbit/s), HID boot
  keyboard** (interface class 03, driver `usbhid`).
- **There is no PS/2 controller**: the same dmesg contains exactly one i8042 line —
  `[1.335267] i8042: PNP: No PS/2 controller found.` — and **no** `i8042: controller at 0x60`
  line anywhere in the log (grep over the full 1208-line dmesg: 1 match). PnP ACPI found only
  4 devices, none a `PNP0303` keyboard.
- **USB controllers on this model** (class `0c03`, lspci probe `12cfa4cdb2`):

  | Device | ID | Type | I/O / MEM | IRQ (Linux GSI) |
  |---|---|---|---|---|
  | 00:1d.0 | 8086:27c8 | UHCI #1 (prog-if 00) | I/O `0x2080-0x209f` | 21 |
  | 00:1d.1 | 8086:27c9 | UHCI #2 | I/O `0x2060-0x207f` | 19 |
  | 00:1d.2 | 8086:27ca | UHCI #3 | I/O `0x2040-0x205f` | 18 |
  | 00:1d.3 | 8086:27cb | UHCI #4 | I/O `0x2020-0x203f` | 16 |
  | 00:1d.7 | 8086:27cc | EHCI (prog-if 20) | MEM `0xd0445400`, 1 K | 21 |

  The keyboard is on **UHCI #1 (00:1d.0)** — full-speed devices attach to UHCI (EHCI routes
  them to the companion controller), so the first real-hardware keyboard driver needs a
  **UHCI** driver, not OHCI (the MacBook2,1 has no OHCI; the earlier "UHCI/OHCI?" question
  resolves to: **UHCI + EHCI only**, southbridge is ICH7-M `8086:27b9`).
- **What ports 0x60/0x64 do on this machine is [unverified].** No PNP device claims them and
  Linux never printed a successful controller probe, but the log also doesn't show Linux's
  explicit "No controller found" failure line, so direct port probing behaviour is unclear.
  Note the ACPI EC lives at **0x66/0x62** (`ACPI: EC: EC_CMD/EC_SC=0x66, EC_DATA=0x62` in the
  same dmesg), i.e. a different port pair — do not confuse them. Our PS/2 probe must treat
  `0x64 == 0xFF` (or a hang/timeout waiting for IBF to clear) as "no controller" and give up
  gracefully.

**Consequence for the plan:** PS/2 development happens in **QEMU** (§2.2); real-hardware
keyboard input is a later **UHCI + HID boot-protocol** milestone. External USB keyboards on
the MacBook will need the same stack.

### 2.2 What QEMU provides by default (our current `cargo xtask` flags)

- QEMU's manual: *"The QEMU PC System emulator simulates the following peripherals: …
  **PS/2 mouse and keyboard**"* (qemu-manpage, §Description). The `pc` machine has an `i8042`
  machine option that defaults to **on** (introduced QEMU 7.0, commit
  `4ccd5fe22feb…` "pc: add option to disable PS/2 mouse/keyboard"; before that it was always
  present).
- Our xtask QEMU arguments (`xtask/src/main.rs:179-198`) are
  `-m 256M -cdrom … -serial stdio -display none -no-reboot -netdev user -device e1000,…` —
  **no `-machine`, no `-nodefaults`, nothing disabling i8042** → the i8042 exists at I/O
  ports `0x60`/`0x64`, wired to **IRQ1 (keyboard) and IRQ12 (mouse)** (`kbd-irq` default 1,
  `mouse-irq` default 12, `i8042.c` property defaults).
- QEMU i8042 behaviour, from `hw/input/pckbd.c`:
  - `kbd_reset`: `mode = KBD_MODE_KBD_INT | KBD_MODE_MOUSE_INT` → **default config byte
    0x03: IRQ1 and IRQ12 already enabled, translation (bit 6) OFF.**
  - IRQ line raised only when output-buffer-full is set **and** `KBD_MODE_KBD_INT` (bit0) is
    set **and** the kbd interface isn't disabled (`kbd_update_irq_lines`).
  - Reading port `0x60` with OBF set **deasserts the IRQ** (`kbd_read_data` →
    `kbd_deassert_irq`); if more bytes are queued the PS/2 layer re-raises it
    (`ps2_read_data`), so a handler should **drain all available bytes** in one ISR.
- QEMU PS/2 keyboard, from `hw/input/ps2.c`:
  - On reset the emulated keyboard is `scancode_set = 2`, `translate = 0`, `scan_enabled = 1`.
  - With translation **off** (QEMU default) the guest receives **scan code set 2** bytes
    raw: make = code, break = `0xF0` + code.
  - Writing the controller config byte with **bit 6 (KCC/translation) set** calls
    `ps2_keyboard_set_translation(1)` and the controller then emits **set 1** (make = code,
    break = `code | 0x80`), using its `translate_table` (which handles the `0xF0` prefix and
    ORs 0x80 for breaks).
  - Keyboard replies: `0xFA` ACK, `0xAA` power-on-reset, ID `0x41` (translated) / `0x83`
    (raw) on `0xF2`; unknown commands answer `0xFE` RESEND.
  - Commands the emulated keyboard honours include `0xF0` (set scancode set), `0xF2`, `0xF3`,
    `0xF4` (enable scanning), `0xF5/0xF6`, `0xFF` (reset), `0xED` (LEDs) — see
    `ps2_write_keyboard`.
- **Firmware handoff caveat [unverified]:** SeaBIOS/GRUB may have already written the config
  byte (a classic BIOS enables translation). Therefore the driver must **read the config byte
  (cmd 0x20) and set bit 6 explicitly** instead of assuming either state — this makes byte
  stream deterministic (set 1) on QEMU regardless of what the firmware left behind.
- **Getting keys into a headless QEMU:** our runs use `-display none` with serial on stdio,
  so there is no GUI keyboard and stdio belongs to the serial console. Key injection must go
  through the HMP monitor (`sendkey a`, `sendkey shift-a`, `sendkey up` …) or QMP
  `input-send-event`; `sendkey` works fine with `-display none`. **Resolved (keyboard
  milestone):** QEMU creates no monitor by default under our arguments, so `qemu_std_args`
  now adds an explicit endpoint. The planned unix socket (`-monitor unix:/iso/qemu.sock`)
  **failed empirically**: Docker Desktop does not relay unix-socket connections through bind
  mounts — the socket file appears on the host but `connect(2)` gets `ECONNREFUSED` (probed
  2026-11-21, Docker Desktop 27.4.0). What works is **TCP**: QEMU binds `tcp:0.0.0.0:PORT`
  inside the container (a service bound to the container loopback is unreachable via `-p`,
  which forwards to eth0), Docker publishes it with `-p 127.0.0.1:PORT:PORT`, and a host QEMU
  binds `tcp:127.0.0.1:PORT` directly; the port is derived from the checkout path so parallel
  worktrees don't collide. HMP key names are QEMU's `QKeyCode` enum (`qapi/ui.json`): letters
  as-is, `spc`, `ret`, `shift-k`, `minus`. (For comparison, QEMU's own docs use
  `-serial mon:stdio -display none` to mux monitor+serial — rejected: it would steal stdin
  from the serial console in `cargo xtask run`.)
- For the **later USB-HID milestone**, QEMU also offers `-device usb-kbd` (manpage:
  *"Standard USB keyboard. Will override the PS/2 keyboard (if present)"*) plus a USB
  controller (`-device piix3-usb-uhci` if the machine doesn't already have one —
  **[unverified]** whether our default `pc` machine creates one without `-usb`); that lets us
  develop UHCI+HID in QEMU before touching the MacBook.

### 2.3 The i8042 controller: ports, status byte, commands, init

Sources: OSDev "I8042 PS/2 Controller", QEMU `pckbd.c` (bit definitions match), Linux
`drivers/input/serio/i8042.c`.

**Ports**

| Port | Read | Write |
|---|---|---|
| `0x60` | output buffer — next byte for the CPU (keyboard data / command reply) | data byte → keyboard (or to controller, if the previous `0x64` write was a command) |
| `0x64` | **status register** | **command register** |

**Status register (read `0x64`)** — QEMU `KBD_STAT_*` names:

| bit | mask | name | meaning |
|---|---|---|---|
| 0 | 0x01 | OBF | output buffer full: a byte is waiting at `0x60`. **This is the poll bit** |
| 1 | 0x02 | IBF | input buffer full: controller busy — **wait for this to clear before every write** |
| 2 | 0x04 | SYS | system flag (QEMU calls it "self test successful") |
| 3 | 0x08 | CMD/DATA | QEMU: "last write was a command write (0=data)" — rarely needed |
| 4 | 0x10 | UNLOCKED | keyboard lock (0 = locked) |
| 5 | 0x20 | AUX_OBF | the pending byte is from the aux (mouse) channel — **discard for keyboard-only** |
| 6 | 0x40 | GTO | receive/transmit timeout |
| 7 | 0x80 | PERR | parity error |

**Controller config/mode byte** (command `0x20` reads it into `0x60`; command `0x60` makes the
next `0x60` write the new value) — QEMU `KBD_MODE_*`:

| bit | mask | name | meaning |
|---|---|---|---|
| 0 | 0x01 | KBD_INT | keyboard data raises **IRQ1** |
| 1 | 0x02 | MOUSE_INT | aux data raises IRQ12 (leave off for us; QEMU defaults it on) |
| 2 | 0x04 | SYS | system flag |
| 3 | 0x08 | NO_KEYLOCK | keylock doesn't affect the keyboard |
| 4 | 0x10 | DISABLE_KBD | disable keyboard interface |
| 5 | 0x20 | DISABLE_MOUSE | disable aux interface |
| 6 | 0x40 | KCC / XLATE | **scan-code translation: set 2 → set 1** (the bit we set) |
| 7 | 0x80 | RFU | reserved |

**Controller commands** (write to `0x64`; replies arrive at `0x60` with OBF set):

| cmd | effect (QEMU `KBD_CCMD_*`) |
|---|---|
| 0x20 | read config byte → `0x60` |
| 0x60 | next `0x60` byte is the new config byte |
| 0xAA | controller self-test → `0x55` (also sets SYS flag) |
| 0xAB | keyboard-interface test → `0x00` |
| 0xAE / 0xAD | enable / disable keyboard interface |
| 0xA8 / 0xA7 | enable / disable aux interface |
| 0xA9 | aux interface test → `0x00` |
| 0xC0 | read input port → `0x80` |
| 0xD0 / 0xD1 | read / write output port (0xD1 + byte with bit0=0 ⇒ **CPU reset**) |
| 0xD2 / 0xD3 | inject a byte into the keyboard / aux output buffer |
| 0xD4 | next byte goes to the mouse |
| 0xDD / 0xDF | A20 off / on — **irrelevant for us** (long mode is already on) |
| **0xFE** | pulse reset line — **QEMU treats this as a VM reset request. Never send it.** |
| 0xFF / 0xF0 | pulse P2 bits / no-op |

Keyboard-side commands (write to `0x60`, one at a time, wait for `0xFA`):
`0xF0` then `0x00` (query set) / `0x01..0x03` (select set), `0xF2` (ID), `0xF3` (typematic),
`0xF4` (enable scanning), `0xF5`/`0xF6` (disable/restore default), `0xFF` (reset → `0xFA`,
`0xAA`), `0xED` (LEDs).

**Initialization sequence (minimal, robust):**

1. Before *every* write: poll `0x64` until IBF (bit 1) is clear (bounded retry).
2. Flush: while OBF (bit 0) set, read `0x60` (if AUX_OBF set, it's mouse data — drop it).
3. Read config (`0x20` → `0x60`); set **bit 0 (IRQ1)** and **bit 6 (translation)**; keep bit 1
   (IRQ12) cleared so mouse bytes never interrupt us; leave bits 4/5 clear (interfaces on).
   Write back (`0x60` cmd, then value). On QEMU this flips the byte stream to set 1
   (§2.2).
4. Optional probe of controller presence: `0xAA` self-test expecting `0x55`, and/or `0xAB`
   expecting `0x00`. On the MacBook expect timeout/`0xFF` → declare "no controller" and stop
   (§2.1). **Re-read/rewrite the config byte after `0xAA`** — real controllers may reset it
   during self-test **[unverified]**.
5. Optional: enable the keyboard interface (`0xAE`), then tell the keyboard to enable scanning
   (`0xF4` → `0xFA`). QEMU's keyboard already has scanning enabled by default, so this is
   belt-and-braces.
6. Unmask IRQ1 in the PIC (§2.5) — only when ready to take interrupts; until then, poll OBF.

Reading a scancode: poll `0x64` for OBF, then read `0x60`. Reading `0x60` is also what clears
OBF and deasserts IRQ1 (§2.2). Never read `0x60` without OBF set (returns stale data).

### 2.4 Scan code set 1 and a minimal US layout

Reference: OSDev "Scan Code Set 1" / "PS/2 Keyboard". With translation enabled (our choice,
§2.2 step 3) the wire protocol is set 1:

- **Make** (press) = the code; **break** (release) = same code **OR 0x80**.
- **`E0` prefix** marks extended keys: sequence is `E0 <code>` (make) / `E0 <code|0x80>`
  (break). Track a sticky `e0` flag across bytes.
- **`E1` prefix** only for Pause: `E1 1D 45 E1 9D C5` (make only, no break).
- Typematic repeat re-sends the *make* code; treat repeats as repeated key-down (or ignore).

**Base codes you need for a US shell** (make codes; add 0x80 for break):

| Code | Key | Code | Key | Code | Key |
|---|---|---|---|---|---|
| 0x01 | Esc | 0x1E | a | 0x35 | / |
| 0x02..0x0B | 1..9,0 | 0x1F | s | 0x36 | RShift |
| 0x0C | - | 0x20 | d | 0x37 | keypad * |
| 0x0D | = | 0x21 | f | 0x38 | LAlt |
| 0x0E | Backspace | 0x22 | g | 0x39 | Space |
| 0x0F | Tab | 0x23 | h | 0x3A | **CapsLock** |
| 0x10 | q | 0x24 | j | 0x3B..0x44 | F1..F10 |
| 0x11 | w | 0x25 | k | 0x45 | NumLock |
| 0x12 | e | 0x26 | l | 0x46 | ScrollLock |
| 0x13 | r | 0x27 | ; | 0x47..0x53 | keypad 7..9,4..6,1..3,0,. (also Home/↑/PgUp/←/→/End/↓/PgDn/Ins/Del when NumLock off) |
| 0x14 | t | 0x28 | ' | 0x57 | F11 |
| 0x15 | y | 0x29 | ` | 0x58 | F12 |
| 0x16 | u | 0x2A | **LShift** | 0x1C | Enter (main) |
| 0x17 | i | 0x2B | \ | 0x1D | **LCtrl** |
| 0x18 | o | 0x2C | z | | |
| 0x19 | p | 0x2D | x | | |
| 0x1A | [ | 0x2E | c | | |
| 0x1B | ] | 0x2F | v | | |
| | | 0x30 | b | | |
| | | 0x31 | n | | |
| | | 0x32 | m | | |
| | | 0x33 | , | | |
| | | 0x34 | . | | |

**Extended (`E0`) keys:** `E0 1C` keypad Enter · `E0 35` keypad / · `E0 1D` RCtrl ·
`E0 38` RAlt · `E0 5B` LWin · `E0 5C` RWin · `E0 5D` Menu · `E0 47/48/49` Home/Up/PgUp ·
`E0 4B/4D` Left/Right · `E0 4F/50/51` End/Down/PgDn · `E0 52/53` Insert/Delete ·
PrtScr is `E0 2A E0 37` (make) / `E0 B7 E0 AA` (break).

**US layout, punctuation that needs Shift** (unshifted → shifted):
`1..0 → !"#$%^&*()`, `` ` → ~ ``, `- → _`, `= → +`, `[ → {`, `] → }`, `\ → |`,
`; → :`, `' → "`, `, → <`, `. → >`, `/ → ?`. Everything else is a plain letter/digit.

**State machine:**

1. `shift = (count of currently-held LShift/RShift) > 0` — set on make of 0x2A/0x36, clear on
   break; both keys must be tracked independently (press both, release one → still shifted).
2. `caps` toggles **on CapsLock make only** (0x3A); ignore its break. **[unverified]**
   whether to ignore typematic repeats of CapsLock — safest is to latch "already toggled
   until next break".
3. Letter case: `upper = shift XOR caps`. Non-letter characters: `upper = shift` only —
   CapsLock never affects digits/punctuation.
4. Modifiers Ctrl (0x1D / `E0 1D`) and Alt (0x38 / `E0 38`) tracked the same way; useful for
   shell shortcuts later.
5. Ignore keys with no mapping rather than panicking (F-keys, keypad, Win/Menu).

### 2.5 IRQ1 path through our kernel (IDT / PIC)

Current state (read from this checkout):

- **PIC remap + mask** (`kernel/src/pic.rs:22-38`): master vectors start at 32, slave at 40;
  masks are written as **master `0xFE` (only IRQ0 unmasked)** and slave `0xFF`
  [pic.rs:34-36]. IRQ1 is master bit 1 → to enable it the mask becomes **`0xFC`**
  (clear bit 1; keep IRQ2 cascade as-is — it's already effectively masked? note: 0xFC also
  leaves bit1 cleared and everything else as before; cascade bit2 stays set in 0xFC? **0xFC
  = 1111_1100 clears bits 0 and 1** — that would also re-mask IRQ0! The correct target for
  "IRQ0 + IRQ1" is **`0xFC`**… precisely: current 0xFE = `1111_1110` (IRQ0 on). Adding IRQ1
  ⇒ `1111_1100` = 0xFC, which keeps bit0=0 (IRQ0 still enabled) and bit1=0 (IRQ1 enabled).
  Yes — 0xFC is correct for both.)
- **IDT** (`kernel/src/idt.rs:101-127`): vectors 0..=47 are all installed from
  `isr_stub_table`; after the PIC remap, **IRQ1 arrives at vector 33 = 0x21** (IRQ_n → 32+n).
- **Dispatcher** (`kernel/src/idt.rs:183-186`): today vector 33 falls into
  `vector @ 33..=47 => { serial_println!("EXC: unexpected IRQ …"); pic::eoi(vector-32); }`.
  That branch is where the keyboard handler replaces the "unexpected" print.

**What the IRQ1 handler must do (in order):**

1. Read status `0x64`; while OBF (bit 0) set:
   - read `0x60` (this also deasserts the controller's IRQ line and, in QEMU, re-raises it if
     more bytes are queued — draining avoids lost edges on the 8259);
   - if AUX_OBF (bit 5) set, discard (mouse — IRQ12 stays masked);
   - else push the byte into a **scancode ring buffer** (fixed-size, single-producer
     (ISR) / single-consumer (shell) — a `u8` ring is enough; the existing serial input loop
     at `main.rs:165` becomes a second feeder into the same line discipline).
2. Decode E0/E1 state and push ASCII/`Key` events (the set-1 state machine of §2.4) —
   either in the ISR (cheap tables) or lazily in the shell loop (preferred: keeps the ISR
   tiny).
3. `crate::pic::eoi(1)` — the existing `eoi` already handles cascade for IRQ ≥ 8; IRQ1 only
   needs the master EOI [pic.rs:42-49].
4. Return; the existing `Frame`/`interrupt_dispatch` contract is unchanged
   [idt.rs:142-147].

**Enabling IRQ1 involves exactly two things** beyond the handler: change the master mask
write from `0xFE` to `0xFC` (or do it dynamically via a `pic::unmask(irq)` helper —
preferred so the default stays timer-only), and make sure the i8042 config byte has bit 0
set (§2.3 step 3 — QEMU already defaults it on, but set it explicitly).

Also note: `sti` is already in effect by the time IRQ0 ticks (the smoke test asserts
`INT_OK`), so no further CPU-side enable is needed. Optional hardening: handle spurious IRQ7
(`pic.rs` has no ISR check today — acceptable to skip initially).

### 2.6 What the minimal keyboard driver skips

- No mouse/IRQ12, no aux-byte handling beyond discarding.
- No typematic reconfiguration, no LED control (`0xED`), no keyboard reset (`0xFF`) —
  assume scanning is on (QEMU default; firmware state on QEMU **[unverified]**).
- No set 2/set 3 decoding (we force set 1 via translation), no `E1`/Pause handling beyond
  ignoring, no PrintScreen niceties, no Win/Menu keys, no keymap beyond US.
- No A20 (0xDD/0xDF), no output-port games, no controller self-test on the happy path.
- No USB — that's the real-hardware milestone (UHCI `8086:27c8` @ `0x2080`, HID boot protocol,
  keyboard at port 2 of `00:1d.0`, VID `05ac` PIDs `021a/021b`).

### 2.7 Milestone plan — keyboard

*Status (2026-11-21, keyboard milestone): steps 1, 2, 3 and 5 landed in QEMU — polled
i8042 bring-up (`kernel/src/keyboard.rs`, config byte = IRQ1 + translation → set 1, bounded
waits, fail-soft), `pc-keyboard` set-1/US decoding (evaluated in
`docs/pc-keyboard-eval.md`), serial+keyboard multiplexed into one line discipline, and a
`KEYBOARD_OK` smoke phase driven by HMP `sendkey`. Steps 4 (IRQ1), 6 (real-hardware i8042
probe) and 7/8 (UHCI + HID) remain.*

1. **[QEMU]** ✅ Add a key-injection endpoint to `qemu_std_args` (`xtask/src/main.rs:179-198`) —
   QMP unix socket or HMP telnet — so tests can run `sendkey`. Verify manually that
   `sendkey a` reaches the guest once the driver exists. (Needs an xtask change; out of
   scope for this document's file, listed here as the first step.)
2. **[QEMU]** ✅ *Polled driver first, no IRQ:* implement the i8042 init of §2.3 (config ←
   `IRQ1 + translation`), then in the boot/shell loop poll `0x64` bit0 and print raw scancode
   bytes on the serial console. Test matrix: `sendkey a` → `1E 9E`; `sendkey shift-a` →
   `2A 1E 9E AA`; `sendkey up` → `E0 48 E0 C8`; `sendkey ret` → `1C 9C`. This validates the
   set-1 assumption without touching the PIC.
3. **[QEMU]** ✅ *Decode:* add the set-1 → ASCII state machine (§2.4); print the resulting
   characters (`a`, `A` with CapsLock via `sendkey caps_lock`, `_` via `sendkey shift-minus`).
4. **[QEMU]** *Interrupts:* unmask IRQ1 (`0xFC`), replace the vector-33 branch in
   `interrupt_dispatch` [idt.rs:183] with the drain+queue+EOI handler (§2.5); confirm the
   serial "unexpected IRQ" line no longer appears and keys arrive while the CPU is idle in
   the shell loop.
5. **[QEMU]** ✅ *Wire into the console:* feed decoded characters into the same input path the
   serial shell uses (`main.rs:165` loop over `serial.rs:57 read_byte` — the shell that
   `cargo xtask run` drops into with `help`, asserted in smoke via the `… → INT_OK → SHELL_OK`
   marker chain in AGENTS.md), so the shell reads either source. Add a `KBD_OK`-style serial
   marker (and optionally a QMP-driven `sendkey` step to `cargo xtask smoke`) so regressions
   are caught headlessly.
6. **[Real HW, probe only]** Guarded i8042 detection (§2.1): try `0x64`/`0x60` reads with a
   timeout; expect "no controller" on the MacBook — log it and continue. This step is cheap
   and removes the uncertainty about ports 0x60/0x64 on this machine.
7. **[Real HW]** *UHCI + HID keyboard:* enumerate PCI `00:1d.0` (`8086:27c8`, I/O `0x2080`),
   enable the controller, find device 2 (VID `05ac`, PID `021a/021b`, full-speed), read the
   HID descriptor, set the boot protocol, and **poll** the interrupt-IN endpoint (no IRQ
   needed at first) → HID usage IDs → same ASCII state machine as step 3 (Shift/Caps live in
   the report, not in scan codes). Test on the MacBook with a DVD boot; external USB keyboards
   should work through the same path.
8. **[Later]** Move UHCI to interrupt-driven (resolve its 8259 line — same PIRQ uncertainty
   as §1.1), add mouse/touchpad if desired, EHCI only if a high-speed device is needed (the
   keyboard is full-speed and stays on UHCI).

---

## Section 3 — Remote hardware validation setup (landed 2026-11-21, user-approved)

Everything below was provisioned on the real MacBook (`luis@192.168.1.71`, key
`~/.ssh/mac_legacy_rescue`, hostname `macbook21`) with explicit user approval
(QEMU install + GRUB entry). Reversible: remove `/etc/grub.d/15_reemplazo` +
`update-grub` and uninstall `qemu-system-x86`.

### QEMU/KVM on the MacBook (baseline + speed tests without rebooting)

- Installed: `qemu-system-x86` (Debian); `luis` added to group `kvm` (use
  `sg kvm -c "…"` — group applies to new login sessions).
- **Validated 2026-11-21: our ISO booted to `SHELL_OK` — 20/20 boot-phase
  markers — on the real Core2 T7400 under `-enable-kvm -cpu host`**, no
  SIGILL/FATAL: the x86-64-v1 baseline (SSSE3 ceiling) is clean on real
  silicon, and DNS/TCP/TLS/HTTP/git/ssh-KEXINIT all worked through slirp.
  QEMU exit was `timeout`-124 (expected: no keyboard phase without sendkey).
- Reproduce (ISO must be re-scp'd after every build — see below):

```
scp -i ~/.ssh/mac_legacy_rescue target/iso-root/os.iso luis@192.168.1.71:~/reemplazo-os.iso
ssh -i ~/.ssh/mac_legacy_rescue luis@192.168.1.71 'sg kvm -c "timeout 75 qemu-system-x86_64 \
  -enable-kvm -cpu host -m 512 -cdrom ~/reemplazo-os.iso -display none -serial stdio \
  -netdev user,id=n0 -device e1000,netdev=n0"'
```

### GRUB entry for remote reboot cycles (one-shot, Debian stays default)

- `/boot/reemplazo/kernel.elf` (scp'd `target/iso-root/boot/kernel.elf`;
  re-scp after every build), `/etc/grub.d/15_reemplazo` with
  `multiboot2 /boot/reemplazo/kernel.elf` (Debian runs pure BIOS
  i386-pc GRUB — `multiboot2.mod` present, verified).
- `grub-script-check` passes; **`GRUB_DEFAULT` untouched (Debian remains the
  default boot)** — the entry is selected one-shot with:

```
sudo grub-reboot reemplazo && sudo reboot   # boots OUR OS once; next reboot returns Debian
```

  Verified `grub-reboot` writes `next_entry=reemplazo`; the pending value was
  cleared afterwards (`sudo grub-editenv /boot/grub/grubenv unset next_entry` —
  note the correct syntax: FILE then COMMAND).

### Recovery rule (until USB HID + sky2 + sshd exist)

Booting our OS on real hardware is a **one-way trip**: no keyboard (MacBook
keyboard is USB/UHCI — milestone pending), no network (sky2 driver — in
progress), no serial port. If our OS is running on the MacBook, the only way
back is the **physical power button**. Only run `grub-reboot` when someone is
physically near the machine, or after sky2+sshd land (then our OS is reachable
over the network).
---

## Section 4 — AHCI (SATA): the MacBook ICH7 disk path (landed)

Milestone `AHCI_OK`. Driver: `kernel/src/ahci.rs` (MMIO + DMA glue) over
the `ahci-wire` crate (registers, FIS, command/PRDT layouts, geometry,
IDENTIFY decode — `no_std`, `forbid(unsafe_code)`, 27 adversarial host
tests). Every offset/bit below is cited from the AHCI 1.3.1 spec and
cross-checked against QEMU 10.0.13's `hw/ide/ahci.c`
(`ahci-internal.h`); nothing here is remembered.

### 4.1 Where the controller is, and what QEMU models

- **Binding rule**: PCI class `01h` (mass storage), sub-class `06h`
  (SATA), programming interface `01h` (AHCI) — the PCI Local Bus Spec
  class-code table. The driver binds by *function*, not by vendor/device
  ID: the ICH7's SATA device ID varies with configuration, and firmware
  (SeaBIOS on QEMU, Apple EFI/BIOS emulation on the MacBook) assigns the
  BARs.
- **ABAR = BAR5** (config offset `0x24`), a **32-bit memory** BAR
  (AHCI 1.3.1 §2.1.8; Linux `libahci` maps PCI BAR 5 as
  `AHCI_PCI_BAR`). The driver reads the BAR — it never hardcodes an
  address — masks its flag bits (`pci::mem_bar_address`), and refuses
  one above 4 GiB (outside `entry.S`'s identity map) rather than
  faulting.
- **QEMU model**: the smokes run QEMU's `ich9-ahci` on the default
  i440fx machine:

  ```
  -device ich9-ahci,id=sata
  -drive file=...,if=none,id=ahci0,format=raw
  -device ide-hd,drive=ahci0,bus=sata.1
  ```

  Port `sata.1` is AHCI port index 1, which exercises non-zero port
  arithmetic. Measured on the smoke (QEMU 10.0.13, `reemplazo-tools`):
  ABAR `0xfebf1000`, `CAP 0xc0141f05` (32 command slots,
  S64A/NCQ/AHCI bits set), `PI 0x0000003f` (6 implemented ports),
  `VS 0x10000` (AHCI 1.0), disk `QEMU HARDDISK` 131072 sectors
  (64 MiB) at port 1.
- **The real machine**: the MacBook2,1's 120 GB SATA disk hangs off the
  ICH7 south bridge in **AHCI** mode, which is exactly why the legacy
  IDE driver (`ata.rs`, ports 0x1F0/0x3F6) cannot see it. Real-hardware
  validation of the sequence below (PxSIG/PxSSTS values, COMRESET
  timing, the ICH7's CAP.NCS/PI) is **pending**; QEMU is the only
  executed test bed so far.

### 4.2 Register summary used (AHCI 1.3.1 §3)

| Register | Offset | Use here |
|---|---|---|
| `CAP` | `0x00` | `CAP.NCS[12:8]` = command slots − 1; `CAP.S64A[31]` (informational) |
| `GHC` | `0x04` | `GHC.AE[31]` = 1 (AHCI enable); read back as a write-path check |
| `IS` | `0x08` | not used (interrupts stay masked; polling only) |
| `PI` | `0x0C` | one bit per implemented port |
| `VS` | `0x10` | printed (version) |
| Port *n* window | `0x100 + 0x80·n` | (§3.3) |
| `PxCLB/PxCLBU` | `+0x00/+0x04` | command-list physical address (1 KiB aligned) |
| `PxFB/PxFBU` | `+0x08/+0x0C` | received-FIS physical address (256 B aligned) |
| `PxIS` | `+0x10` | write-1-to-clear status; `TFES[30]`, `HBFS[29]`, `HBDS[28]`, `IFS[27]`, `INFS[26]`, `OFS[24]`, `IPMS[23]` = failure |
| `PxCMD` | `+0x18` | `ST[0]`, `SUD[1]`, `POD[2]`, `FRE[4]`, `CCS[12:8]`, `FR[14]`, `CR[15]` |
| `PxTFD` | `+0x20` | status `[7:0]` (`ERR[0]`, `DRQ[3]`, `BSY[7]`), error `[15:8]` |
| `PxSIG` | `+0x24` | `0x00000101` = ATA drive (ATAPI `0xEB140101` is skipped) |
| `PxSSTS` | `+0x28` | `DET[3:0]` = 3 ⇒ device present, PHY up |
| `PxSCTL` | `+0x2C` | `DET=1` ⇒ COMRESET, then `DET=0` |
| `PxSERR` | `+0x30` | write-1-to-clear at bring-up |
| `PxCI` | `+0x38` | one bit per command slot — the command doorbell |

Port command sequence (AHCI 1.3.1 §10.5.1 COMRESET, §10.6.1 start):
if `DET ≠ 3`, assert `PxSCTL.DET = 1` for ≥ 1 ms (one PIT tick,
10 ms, since interrupts are armed before the PCI scan), clear it, wait
for `DET = 3`; then clear `ST` and wait `CR = 0`, clear `FRE` and wait
`FR = 0` (both bounded), program `PxCLB/PxFB`, clear `PxIS/PxSERR`, set
`SUD|POD`, set `FRE` and wait `FR`, set `ST` and wait `CR`. Every wait
is a bounded spin (20 M iterations), so a wedged port fails the probe
instead of hanging boot.

### 4.3 Commands, DMA and coherency

- **Command list**: one 4 KiB frame, 32 headers of 32 bytes
  (AHCI 1.3.1 §4.2.1). Only slot 0 is used (one command in flight);
  header dword 0 = `CFL[4:0]` (5 for a 20-byte H2D FIS) + `W[6]` +
  `PRDTL[31:16]`, dwords 2/3 = command-table address.
- **Command table**: `CFIS` at `+0x00` (the 20-byte Register Host to
  Device FIS, SATA 3.2 §10.3.1), `PRDT` at `+0x80` with one 16-byte
  entry per 4 KiB data frame (§4.3): `DBA/DBAU` (low/high 32 bits),
  reserved, `DBC[21:0] = bytes − 1`, `I[31]` on the last entry.
  Scatter/gather is per-frame, so **no physical contiguity is assumed**
  — the frame allocator's runs need not be adjacent.
- **Commands**: `IDENTIFY DEVICE` `0xEC` (ATA8-ACS2 §7.16; a
  PIO-protocol command whose 512 bytes the HBA still moves through the
  PRDT — QEMU `ahci_pio_transfer()`, and how libahci issues it), then
  LBA48 `READ DMA EXT` `0x25` / `WRITE DMA EXT` `0x35` (§7.20/§7.62).
  The caller's 1..=256-sector contract (the IDE driver's) is split into
  two 128-sector (64 KiB, 16-frame) commands by host-tested arithmetic
  (`ahci-wire::geometry::split_request`); PRDTL is therefore ≤ 16.
- **Completion**: poll `PxCI` bit 0; failure first if any `PxIS` error
  bit is set (the device's `PxTFD.ERR` word names the ATA error), else
  success when `PxCI` clears and `PxTFD` has neither `BSY` nor `ERR`.
  Stale `PxIS` bits are cleared before each command and after each
  completion.
- **Coherency**: `memory::alloc()` frames are identity-mapped
  (`entry.S`, first 4 GiB, default WB type), so the physical addresses
  handed to the HBA are the same bytes the CPU writes. x86 PCI
  bus-master DMA is cache-coherent (no IOMMU here, no non-coherent
  memory type), so no explicit flush/invalidate is needed; ordering *is*:
  a `fence(SeqCst)` sits between the descriptor/FIS/PRDT writes and the
  `PxCI` write, the same discipline `e1000::transmit` uses for TDT.
  The frames are freed on `Drop` after the port's engines are stopped.

### 4.4 FAT16 stays on the IDE disk; what is still open

The smoke's `AHCI_OK` is **additive and read-only**: the installer's
source volume is copied to `disk-ahci.img`, attached through
`ich9-ahci`, and the driver proves PCI probe → port bring-up →
`IDENTIFY DEVICE` → LBA0 read → the installer magic. The FS/GPT/install
proofs keep running on the IDE disks, so `BLK_OK → FAT_OK → … →
NETINST_OK` and the installed disk's boot phase are byte-identical.
When **no** IDE disk answers (the MacBook), the AHCI disk becomes the
block *source* automatically (`ata::Disk::Ahci`) and the same
filesystem/install code runs on it.

Open items: IRQ-driven completion (PIC IRQ10/11 is still masked — the
driver polls), NCQ (`READ/WRITE FPDMA QUEUED`, one command in flight
today), port multipliers, hot-plug, `SET FEATURES`/`FLUSH CACHE`
(`fat::write`'s crash-consistency note applies unchanged), an
AHCI write-round-trip marker in the smoke (the write path runs only
when AHCI is the source), and real ICH7 validation (CAP/PI, reset
timing, `PxSIG`).


## Sources

**Linux sky2 driver (line numbers in this document):**
- `drivers/net/ethernet/marvell/sky2.c` —
  https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/marvell/sky2.c
- `drivers/net/ethernet/marvell/sky2.h` —
  https://raw.githubusercontent.com/torvalds/linux/master/drivers/net/ethernet/marvell/sky2.h
- Linux i8042 driver (controller init/commands):
  https://github.com/torvalds/linux/blob/master/drivers/input/serio/i8042.c

**AHCI / SATA documentation and QEMU model:**
- *Serial ATA Advanced Host Controller Interface (AHCI) 1.3.1*, Intel, 2011 —
  https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf
  (§2.1.8 ABAR/class code, §3.1 generic host control, §3.3 port registers,
  §4.2 command list/header/table, §4.3 PRDT, §10.5 COMRESET, §10.6 start).
- *Serial ATA 3.2* §10.3 — Register Host to Device / Device to Host / PIO Setup /
  Set Device Bits FIS layouts (https://sata-io.org/).
- *ATA8-ACS2* §7.1/§7.16/§7.20/§7.62 — Error register, IDENTIFY DEVICE,
  READ DMA EXT, WRITE DMA EXT (INCITS 482-2012).
- QEMU `hw/ide/ahci.c` — https://raw.githubusercontent.com/qemu/qemu/master/hw/ide/ahci.c
  and `hw/ide/ahci-internal.h` —
  https://raw.githubusercontent.com/qemu/qemu/master/hw/ide/ahci-internal.h
  (register enum, `PORT_CMD_*`, `PORT_IRQ_*`, `AHCICmdHdr`, `AHCI_SG`,
  `handle_reg_h2d_fis`, `ahci_populate_sglist`, `ahci_pio_transfer`).
- Linux `drivers/ata/libahci.c` + `include/linux/libata.h` —
  https://github.com/torvalds/linux/tree/master/drivers/ata (AHCI_PCI_BAR = 5,
  IDENTIFY over the PRDT, bounded waiting in libata-core).
- PCI Local Bus Spec 3.0 §6.2.5.1 (BAR layout) and the class-code table
  (01h/06h/01h) — https://pcisig.com/specifications.

**QEMU (behaviour of the emulated i8042 / PS/2 keyboard):**
- `hw/input/pckbd.c` — https://raw.githubusercontent.com/qemu/qemu/master/hw/input/pckbd.c
- `hw/input/ps2.c` — https://raw.githubusercontent.com/qemu/qemu/master/hw/input/ps2.c
- QEMU manpage (default peripherals incl. "PS/2 mouse and keyboard", `-device usb-kbd`,
  machine option `i8042=off`): https://www.qemu.org/docs/master/system/qemu-manpage.html
- `pc: add option to disable PS/2 mouse/keyboard`, QEMU commit
  `4ccd5fe22feb95137d325f422016a6473541fe9f` (QEMU 7.0, i8042 default ON).
- QEMU `hw/net` device list (no Marvell Yukon model): https://github.com/qemu/qemu/tree/master/hw/net

**PS/2 / i8042 documentation:**
- OSDev — I8042 PS/2 Controller: http://wiki.osdev.org/I8042_PS/2_Controller
- OSDev — PS/2 Keyboard: https://wiki.osdev.org/PS/2_Keyboard
- OSDev — Scan Code Set 1: https://wiki.osdev.org/Scan_Code_Set_1

**Real MacBook2,1 hardware (linux-hardware.org probes):**
- lspci — probe `12cfa4cdb2`: https://linux-hardware.org/?log=lspci&probe=12cfa4cdb2
- lspci_all — probe `12cfa4cdb2`: https://linux-hardware.org/?log=lspci_all&probe=12cfa4cdb2
- dmesg (i8042 line, UHCI/EHCI, EC, NIC BARs) — probe `d8b686d7fe`:
  https://linux-hardware.org/?log=dmesg&probe=d8b686d7fe
- input_devices (keyboard `Bus=0003 … Phys=usb-0000:00:1d.0-2/input0`) — probe `12cfa4cdb2`:
  https://linux-hardware.org/?log=input_devices&probe=12cfa4cdb2
- lsusb / USB table (`05ac:021b Internal Keyboard/Trackpad`) — probe `c98f5d17c5`:
  https://linux-hardware.org/?probe=c98f5d17c5

**This repository:**
- `kernel/src/pic.rs` (remap, masks `0xFE`/`0xFF`, `eoi`), `kernel/src/idt.rs`
  (vector 33 branch at lines 183-186), `kernel/src/serial.rs:57` (`read_byte`),
  `kernel/src/main.rs:165` (input loop), `xtask/src/main.rs:179-198` (QEMU args).

**Explicitly unverified items** (re-verify during the milestones): PIRQ/8259 line for the NIC
on real hardware; behaviour of ports 0x60/0x64 on the MacBook; whether SeaBIOS/GRUB left the
i8042 config byte with translation set; what monitor QEMU creates under our exact
`-serial stdio -display none` arguments; whether the status ring advances with all
interrupts masked; whether the default `pc` machine in our QEMU has a USB controller
without `-usb`; ASPM state of the NIC after Apple EFI/GRUB.

## Fase C — instalación en el MacBook (preparación, 2026-11-22)

Estado verificado en vivo (`ssh -i ~/.ssh/mac_legacy_rescue luis@192.168.1.71`):

- Disco: `sda` (FUJITSU MHW2120BH, 111.8 G), GPT con `sda1`=1 M (bios_grub),
  `sda2`=102.4 G (Debian), `sda3`=9.3 G. DVD `sr0` MATSHITADVD-R UJ-857E.
- firmware `MB21.88Z.00A5.B07.0706270922` (32-bit Apple EFI + BIOS emulation).
- GRUB tiene la entrada `menuentry "reemplazo"` (kernel en
  `/boot/reemplazo/kernel.elf` + módulo `sshd.bin`); `GRUB_DEFAULT=0` (Debian),
  sin `next_entry` pendiente. El ciclo usa `sudo grub-reboot reemplazo && sudo reboot`.
- **LBA0 de `/dev/sda` NO lleva el wipe-marker `reemplazo-target-v1`** (verificado
  con `dd if=/dev/sda bs=512 count=1 | strings`). El installer lo rechazará —
  es la salvaguarda que impide formatear el disco sin confirmación.

Antes de instalar hay que, **con confirmación explícita del operador**, grabar el
marker en LBA0 del disco destino (offset 62 del sector, sin tocar BPB ni `55 AA`).
Ese paso destruye la tabla de particiones actual de Debian y solo debe hacerse
cuando el operador esté delante de la máquina y haya decidido reemplazar Debian.
No está automatizado a propósito.
