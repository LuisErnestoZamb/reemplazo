//! Driver registry for devices that were missing from the first
//! bring-up inventory. Each driver is additive and fail-closed: absent
//! hardware means no output, and a wedged controller becomes one log
//! line, never a hung boot.
//!
//! New drivers are registered here and in `hwdetect` (so a successfully
//! initialised device stops being tagged `NEEDS_DRIVER`).

use alloc::format;

use crate::pci::Scan;

static mut SMBUS_OK: bool = false;
static mut EHCI_OK: bool = false;
static mut SD_OK: bool = false;

/// True when a driver in this kernel successfully brought the device
/// up. Used by the inventory to stop advertising it as undriven.
pub(crate) fn covers(dev: &pci::Device) -> bool {
    // SAFETY: single-core boot, written once by `init`, read later.
    unsafe {
        if (dev.vendor_id, dev.device_id) == (0x8086, 0x27DA) {
            return SMBUS_OK;
        }
        if dev.class == 0x0C && dev.subclass == 0x03 && dev.prog_if == 0x20 {
            return EHCI_OK;
        }
        if dev.class == 0x11 && dev.subclass == 0x01 {
            return SD_OK;
        }
    }
    false
}

fn report(text: &str, code: u8) {
    let mut tag = [0u8; 112];
    let n = text.len().min(tag.len());
    tag[..n].copy_from_slice(&text.as_bytes()[..n]);
    crate::logdisk::log(code, &tag[..n]);
}

/// Bring up every optional driver, recording one summary line.
pub(crate) fn init(scan: &Scan) {
    let smbus = crate::smbus::probe(scan);
    let ehci = crate::ehci::probe(scan);
    let sd = crate::sdhost::probe(scan);
    // SAFETY: see `covers`.
    unsafe {
        SMBUS_OK = smbus;
        EHCI_OK = ehci;
        SD_OK = sd;
    }
    let line = format!(
        "drivers: smbus={} ehci={} sd={}",
        u8::from(smbus),
        u8::from(ehci),
        u8::from(sd)
    );
    serial_println!("{}", line);
    report(&line, 0xED);
}
