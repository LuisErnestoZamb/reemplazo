//! Boot-time hardware inventory written into the persistent log.
//!
//! Bring-up on a new machine needs one question answered without a
//! serial cable: *what did the firmware actually give us, and which of
//! those devices has no driver?* This module walks the PCI scan the
//! kernel already performs, classifies every function against the
//! drivers this repo ships, and records one line per device in
//! `logdisk`. Codes:
//!
//! - `0xD0` — recognised, driver present
//! - `0xD1` — ** recognised but no driver here** (the bring-up backlog)
//! - `0xD2` — platform device outside PCI (SMC, DVD, audio, Wi-Fi…)
//! - `0xD3` — inventory complete
//! - `0xD4` — summary: `devices=N missing=M`

use alloc::format;

use pci::Device;

use crate::pci::Scan;

/// What the repo can drive today. `NEEDS_DRIVER` is the literal tag the
/// host-side `readlog` output is meant to surface.
const NEEDS_DRIVER: &str = "NEEDS_DRIVER";

fn classify(dev: &Device) -> (&'static str, bool) {
    // Exact IDs first — these are the devices the repo actually knows,
    // so a class-code change in a future chipset cannot mislabel them.
    match (dev.vendor_id, dev.device_id) {
        (0x8086, 0x100E) => return ("e1000", false),
        (0x11AB, 0x4362) => return ("sky2", false),
        (0x8086, 0x27C4) => return ("pci-ide (log path)", false),
        (0x8086, 0x27D8) => return ("HDA audio", true),
        (0x8086, 0x27A3) => return ("SD controller", true),
        (0x8086, 0x27CC) => return ("EHCI USB", true),
        (0x8086, 0x27DA) => return ("SMBus / SMC", true),
        (0x168C, 0x0023) | (0x168C, 0x0024) => return ("ath9k wifi", true),
        (0x11C1, 0x5811) => return ("FireWire", true),
        _ => {}
    }
    // Class-code fallbacks for devices whose exact ID we have not
    // pinned yet. Every one of these is either undriven or driven only
    // through a fixed-address path that deserves a hardware check.
    match (dev.class, dev.subclass, dev.prog_if) {
        (0x01, 0x06, _) => ("ahci (QEMU model only)", true),
        (0x01, 0x01, _) => ("ata-pio legacy", false),
        (0x02, 0x00, _) => (NEEDS_DRIVER, true),
        (0x02, 0x80, _) => (NEEDS_DRIVER, true),
        (0x03, _, _) => ("VGA text mirror", false),
        (0x04, _, _) => (NEEDS_DRIVER, true),
        (0x0C, 0x03, 0x00) => ("UHCI keyboard", false),
        (0x0C, 0x03, _) => (NEEDS_DRIVER, true),
        (0x0C, 0x05, _) => (NEEDS_DRIVER, true),
        (0x06, _, _) => ("host bridge", false),
        _ => (NEEDS_DRIVER, true),
    }
}

fn record(code: u8, text: &str) {
    let mut buf = [0u8; 112];
    let n = text.len().min(buf.len());
    buf[..n].copy_from_slice(&text.as_bytes()[..n]);
    crate::logdisk::log(code, &buf[..n]);
}

/// Platform devices the PCI scan cannot see (they hang off SMBus,
/// USB or the ATA channel). Recorded so a future machine's bring-up
/// knows which ones were never enumerated, not merely undriven.
const PLATFORM_NOTES: &[&str] = &[
    "platform: applesmc + coretemp (fan/temp) not read",
    "platform: HDA audio needs a driver",
    "platform: AR5418 a/bgn wifi needs a driver",
    "platform: SuperDrive ATAPI boots ISOs (no driver)",
    "platform: Bluetooth present, disabled",
];

/// Inventory the boot's PCI scan. Never fails the boot: a full record
/// is best-effort, and the serial mirror makes QEMU runs self-describing.
pub(crate) fn run(scan: &Scan) {
    let mut devices = 0usize;
    let mut missing = 0usize;
    for dev in scan.devices.iter().flatten() {
        let (driver, needs) = classify(dev);
        // A driver that actually initialised stops advertising the
        // device as undriven; the label already names the right driver.
        let needs = needs && !crate::drivers::covers(dev);
        let line = format!(
            "PCI {} {:04x}:{:04x} class {:02x}{:02x} {}",
            dev.location, dev.vendor_id, dev.device_id, dev.class, dev.subclass, driver
        );
        record(if needs { 0xD1 } else { 0xD0 }, &line);
        serial_println!("hwdetect: {}", line);
        devices += 1;
        if needs {
            missing += 1;
        }
    }
    for note in PLATFORM_NOTES {
        record(0xD2, note);
        serial_println!("hwdetect: {}", note);
    }
    record(0xD3, "hardware inventory complete");
    let summary = format!("devices={devices} missing={missing}");
    record(0xD4, &summary);
    serial_println!("hwdetect: {}", summary);
}
