//! PCI enumeration via configuration mechanism #1 (I/O ports CF8/CFC).
//!
//! Layout/decoding lives in the `pci` crate (host-tested); this module is
//! only the port I/O and the scan policy: probe function 0 of every
//! bus:device, then functions 1..=7 when header type says multi-function.

use crate::port::{inl, outl};
use pci::{Device, Location, NO_DEVICE_VENDOR};

const CONFIG_ADDRESS: u16 = 0xCF8; // mechanism #1 address port
const CONFIG_DATA: u16 = 0xCFC; // mechanism #1 data port

/// Cap on *stored* devices (real PCs have well under 64); `count` keeps
/// counting beyond the cap so the selftest still sees the true total.
pub const MAX_DEVICES: usize = 64;

/// Result of one full configuration-space scan.
pub struct Scan {
    /// First [`MAX_DEVICES`] functions found, in scan order.
    pub devices: [Option<Device>; MAX_DEVICES],
    /// Total functions found (may exceed what was stored).
    pub count: usize,
}

/// Read one dword of a function's config space.
fn read32(loc: Location, offset: u8) -> u32 {
    let addr = pci::config_address(loc, offset);
    // SAFETY: PCI mechanism #1 is universal on PC-compatible chipsets
    // (i440fx in QEMU, ICH7 on the MacBook); CF8/CFC always exist there.
    unsafe {
        outl(CONFIG_ADDRESS, addr);
        inl(CONFIG_DATA)
    }
}

/// Probe one function: `None` when no device answers (vendor FFFFh).
fn probe(loc: Location) -> Option<Device> {
    let id_word = read32(loc, 0);
    if pci::vendor_id(id_word) == NO_DEVICE_VENDOR {
        return None;
    }
    let class_word = read32(loc, 8);
    let header_word = read32(loc, 0x0C);
    Some(Device {
        location: loc,
        vendor_id: pci::vendor_id(id_word),
        device_id: pci::device_id(id_word),
        class: pci::class_code(class_word),
        subclass: pci::subclass(class_word),
        prog_if: pci::prog_if(class_word),
        revision: pci::revision(class_word),
        header_type: pci::header_type(header_word),
    })
}

/// Scan every bus/device (and non-zero functions when multi-function).
/// Prints each device as found; ~65k config reads worst case, well under
/// a second on both QEMU and the real chipset.
pub fn scan() -> Scan {
    let mut devices = [None; MAX_DEVICES];
    let mut count = 0usize;

    for bus in 0..=u8::MAX {
        for device in 0..32u8 {
            let func0 = Location {
                bus,
                device,
                function: 0,
            };
            let Some(dev0) = probe(func0) else {
                continue;
            };
            serial_println!("pci: {dev0}");
            count += 1;
            if count <= MAX_DEVICES {
                devices[count - 1] = Some(dev0);
            }

            if pci::is_multifunction(dev0.header_type) {
                for function in 1..8u8 {
                    let loc = Location {
                        bus,
                        device,
                        function,
                    };
                    let Some(dev) = probe(loc) else {
                        continue;
                    };
                    serial_println!("pci: {dev}");
                    count += 1;
                    if count <= MAX_DEVICES {
                        devices[count - 1] = Some(dev);
                    }
                }
            }
        }
    }

    Scan { devices, count }
}

/// Machine-checked PCI test: prints `PCI_OK` on success, otherwise dumps
/// context and parks (so `cargo xtask smoke` fails on the marker).
pub fn selftest(scan: &Scan) {
    serial_println!("pci: {} devices found", scan.count);

    if scan.count < 3 {
        serial_println!("FATAL: pci: only {} devices (scan broken?)", scan.count);
        crate::halt();
    }

    // 00:00.0 (host bridge) exists on both QEMU's i440fx and the
    // MacBook's Intel GMCH — its absence means the scan read garbage.
    let want = Location {
        bus: 0,
        device: 0,
        function: 0,
    };
    let has_host_bridge = scan.devices[..]
        .iter()
        .flatten()
        .any(|d| d.location == want);
    if !has_host_bridge {
        serial_println!("FATAL: pci: no host bridge at {want}");
        crate::halt();
    }

    serial_println!("PCI_OK");
}
