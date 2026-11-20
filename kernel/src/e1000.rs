//! Intel 82540EM ("e1000") driver — QEMU's NIC and therefore the
//! development target for the network stack (the MacBook's sky2 has no
//! QEMU model; see AGENTS.md).
//!
//! Register offsets and bit layouts are verified, not remembered:
//! Intel *8254x Family SW Developer's Manual* (CTRL/EERD/RA registers),
//! Linux `e1000_regs.h` (offsets, `E1000_EEPROM_RW_REG_DONE = 0x10`,
//! `E1000_EEPROM_RW_ADDR_SHIFT = 8`), QEMU `hw/net/e1000.c` (EERD
//! emulation, EEPROM words 0..2 = MAC, RAL/RAH reset), u-boot `e1000.h`
//! (`E1000_CTRL_SLU`, `E1000_RAH_AV`).

use crate::pci::{Scan, read32, write32};
use pci::{CMD_BUS_MASTER, CMD_MEMORY_SPACE, E1000_82540EM, INTEL_VENDOR, mem_bar_address};

// --- Register offsets (Intel 8254x SDM / Linux e1000_regs.h) -----------
const CTRL: u32 = 0x00000; // Device Control - RW
const STATUS: u32 = 0x00008; // Device Status - RO
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

/// Poll attempts for an EEPROM read (QEMU answers immediately; real
/// silicon takes microseconds — spin, never sleep: interrupts are off).
const EEPROM_POLLS: u32 = 100_000;

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

/// Probe, enable, verify MMIO, and read the MAC. Prints `E1000_OK` on
/// success; skips cleanly when the NIC is absent (real hardware has sky2,
/// not e1000); parks on a broken device.
pub fn init(scan: &Scan) {
    let Some(dev) = scan.find(INTEL_VENDOR, E1000_82540EM) else {
        serial_println!("e1000: not present (real-hw NIC is sky2) — skipped");
        return;
    };
    let loc = dev.location;
    serial_println!("e1000: found at {loc}");

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
    let from_eeprom = match mac_from_eeprom(mmio) {
        Some(mac) => mac,
        None => fatal("EEPROM read timed out — EERD write path broken?"),
    };
    match mac_from_rar(mmio) {
        Some(rar) if rar != from_eeprom => {
            fatal("EEPROM and RAL/RAH disagree (decode bug?)");
        }
        Some(_) => serial_println!("e1000: RAL/RAH agrees with EEPROM"),
        None => serial_println!("e1000: RAL/RAH invalid (AV clear) — EEPROM authoritative"),
    }
    if !mac_is_sane(&from_eeprom) {
        fatal("MAC is zero/broadcast/multicast");
    }
    serial_println!(
        "e1000: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        from_eeprom[0],
        from_eeprom[1],
        from_eeprom[2],
        from_eeprom[3],
        from_eeprom[4],
        from_eeprom[5]
    );

    serial_println!("E1000_OK"); // machine-checked by `cargo xtask smoke`
}
