//! Minimal SD host-controller bring-up (`class 11/01`, the ICH7's
//! integrated SD slot on the MacBook).
//!
//! Implements the standard SDHCI reset/capability/card-detect path:
//! enough to know whether a card is present and whether the controller
//! is usable. full-card enumeration and DMA are follow-up work; this
//! driver is silent when the controller is absent (QEMU).

use crate::pci::Scan;

const CLASS: u8 = 0x11;
const SUBCLASS: u8 = 0x01;
const POLL_LIMIT: u32 = 2_000_000;

const PRESENT_STATE: usize = 0x24;
const SOFTWARE_RESET: usize = 0x2F; // 8-bit
const CAPABILITIES: usize = 0x40;

unsafe fn read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

unsafe fn write8(base: usize, offset: usize, value: u8) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u8, value) }
}

fn report(text: &str, code: u8) {
    let mut tag = [0u8; 112];
    let n = text.len().min(tag.len());
    tag[..n].copy_from_slice(&text.as_bytes()[..n]);
    crate::logdisk::log(code, &tag[..n]);
}

pub(crate) fn probe(scan: &Scan) -> bool {
    let dev = scan
        .devices
        .iter()
        .flatten()
        .find(|d| d.class == CLASS && d.subclass == SUBCLASS);
    let Some(dev) = dev else {
        return false;
    };
    let command = crate::pci::read32(dev.location, 0x04);
    crate::pci::write32(dev.location, 0x04, command | 0x06);
    let bar = crate::pci::read32(dev.location, 0x10);
    if bar & 1 != 0 {
        return false;
    }
    let base = (bar as usize) & !0xFFusize;
    if base == 0 {
        return false;
    }
    serial_println!("sdhost: controller at {base:#x}");

    // SAFETY: BAR-validated MMIO window, identity-mapped, single core.
    unsafe {
        write8(base, SOFTWARE_RESET, 0x01);
        let mut spins = 0u32;
        while read8_reset(base) & 1 != 0 {
            spins += 1;
            if spins > POLL_LIMIT {
                report("sdhost reset timeout", 0xEB);
                return false;
            }
            core::hint::spin_loop();
        }
        let caps = read32(base, CAPABILITIES);
        let state = read32(base, PRESENT_STATE);
        let card = state & (1 << 16) != 0;
        let line = alloc::format!(
            "sdhost ready at {base:#x} caps={caps:#x} card={}",
            if card { "present" } else { "absent" }
        );
        serial_println!("sdhost: {}", line);
        report(&line, 0xEC);
    }
    true
}

unsafe fn read8_reset(base: usize) -> u8 {
    unsafe { core::ptr::read_volatile((base + SOFTWARE_RESET) as *const u8) }
}
