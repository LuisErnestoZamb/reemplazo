//! Minimal EHCI host-controller bring-up (USB 2.0 high speed).
//!
//! The MacBook has four UHCI controllers (keyboard already works) plus
//! `00:1d.7 EHCI [0c03/20]`. This driver does what a real boot needs
//! before any device class driver can run: reset the controller, leave
//! it running, and inventory the downstream ports so the log can say
//! which one is empty, full-speed (companion-owned) or high-speed.
//!
//! It never touches our UHCI keyboard path, never allocates DMA (that
//! is follow-up work for mass storage), and is silent when absent.

use crate::pci::Scan;

const CLASS: u8 = 0x0C;
const SUBCLASS: u8 = 0x03;
const PROG_IF: u8 = 0x20;
const POLL_LIMIT: u32 = 2_000_000;

const USBCMD: usize = 0x00;
const HCSPARAMS: usize = 0x04;
const PORTSC_BASE: usize = 0x44;
const CMD_RUN: u32 = 1 << 0;
const CMD_RESET: u32 = 1 << 1;

// SAFETY: the base comes from a memory-space BAR with bus-master and
// memory decode enabled by `probe`; identity mapping covers it; single
// core and no other driver touches these registers.
unsafe fn read32(base: usize, offset: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base + offset) as *const u32) }
}

unsafe fn write32(base: usize, offset: usize, value: u32) {
    unsafe { core::ptr::write_volatile((base + offset) as *mut u32, value) }
}

fn report(text: &str, code: u8) {
    let mut tag = [0u8; 112];
    let n = text.len().min(tag.len());
    tag[..n].copy_from_slice(&text.as_bytes()[..n]);
    crate::logdisk::log(code, &tag[..n]);
}

/// Reset + port inventory. Returns `true` when a controller was driven.
pub(crate) fn probe(scan: &Scan) -> bool {
    let dev = scan
        .devices
        .iter()
        .flatten()
        .find(|d| d.class == CLASS && d.subclass == SUBCLASS && d.prog_if == PROG_IF);
    let Some(dev) = dev else {
        return false;
    };
    let command = crate::pci::read32(dev.location, 0x04);
    crate::pci::write32(dev.location, 0x04, command | 0x06); // IO? no: mem + bus master
    let bar0 = crate::pci::read32(dev.location, 0x10);
    if bar0 & 1 != 0 {
        return false; // expected a memory BAR
    }
    let base = (bar0 as usize) & !0xFFusize;
    if base == 0 {
        return false;
    }
    serial_println!("ehci: controller at {base:#x}");

    // SAFETY: see the module-level note.
    unsafe {
        write32(base, USBCMD, CMD_RESET);
        let mut spins = 0u32;
        while read32(base, USBCMD) & CMD_RESET != 0 {
            spins += 1;
            if spins > POLL_LIMIT {
                serial_println!("ehci: reset timeout");
                report("ehci reset timeout", 0xE7);
                return false;
            }
            core::hint::spin_loop();
        }
        write32(base, USBCMD, CMD_RUN);
        let ports = read32(base, HCSPARAMS) & 0x0F;
        serial_println!("ehci: {} ports", ports);
        for port in 0..ports {
            let sc = read32(base, PORTSC_BASE + port as usize * 4);
            let connected = sc & 1 != 0;
            let speed = (sc >> 10) & 0x03;
            let speed_name = match speed {
                1 => "low",
                2 => "full",
                3 => "high",
                _ => "unknown",
            };
            let state = if connected { speed_name } else { "empty" };
            let line = alloc::format!("ehci port {port}: {}", state);
            serial_println!("ehci: port {port}: {state}");
            report(&line, if connected { 0xE8 } else { 0xE9 });
        }
        let line = alloc::format!("ehci ready at {base:#x} ports={ports}");
        report(&line, 0xEA);
    }
    true
}
