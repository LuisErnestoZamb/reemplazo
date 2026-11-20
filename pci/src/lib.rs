//! Pure PCI configuration-space logic: mechanism #1 address layout and
//! config-word field decoding (PCI Local Bus Spec, Config Mechanism #1).
//!
//! No I/O ports here — hardware access lives in the kernel's `pci` module
//! — so every function is host-testable.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// Vendor ID meaning "no device present" (PCI spec: FFFFh is invalid).
pub const NO_DEVICE_VENDOR: u16 = 0xFFFF;

/// Marvell Technology Group (pci.ids).
pub const MARVELL_VENDOR: u16 = 0x11AB;
/// Marvell 88E8053 PCI-E Gigabit Ethernet — the MacBook2,1 NIC driven by
/// Linux's `sky2` (pci.ids / linux sky2.c: `{ PCI_DEVICE(MARVELL, 0x4362) }`).
pub const SKY2_88E8053: u16 = 0x4362;

/// True for the one NIC this OS is ultimately built to drive.
pub fn is_sky2_target(vendor_id: u16, device_id: u16) -> bool {
    vendor_id == MARVELL_VENDOR && device_id == SKY2_88E8053
}

/// Intel (pci.ids) — QEMU's e1000 lives under this vendor.
pub const INTEL_VENDOR: u16 = 0x8086;
/// Intel 82540EM Gigabit Ethernet = QEMU's `e1000` device
/// (`E1000_DEV_ID_82540EM`, seen as `8086:100e` in our own PCI smoke scan).
pub const E1000_82540EM: u16 = 0x100E;

/// PCI command register (offset 0x04), bit 1: Memory Space Enable
/// (PCI Local Bus Spec).
pub const CMD_MEMORY_SPACE: u16 = 1 << 1;
/// PCI command register, bit 2: Bus Master Enable (needed for DMA).
pub const CMD_BUS_MASTER: u16 = 1 << 2;

/// Decode a *memory* base address from BAR0 (+ BAR1 when the BAR is
/// 64-bit). Per the PCI spec the low 4 bits of a memory BAR are flags
/// (bit0 space type, bits2:1 size, bit3 prefetchable) — Linux clears them
/// with `PCI_BASE_ADDRESS_MEM_MASK = ~0x0f`.
///
/// Returns `None` for I/O-space BARs (bit0 set) and unassigned BARs (0).
pub fn mem_bar_address(bar0: u32, bar1: u32) -> Option<u64> {
    if bar0 & 1 != 0 {
        return None; // I/O space BAR
    }
    let is_64bit = (bar0 >> 1) & 0b11 == 0b10; // bits2:1 == 0b10
    let low = u64::from(bar0 & !0xF);
    let addr = if is_64bit {
        low | (u64::from(bar1) << 32)
    } else {
        low
    };
    if addr == 0 {
        None // unassigned
    } else {
        Some(addr)
    }
}

/// A PCI bus:device.function address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub bus: u8,      // 0..=255
    pub device: u8,   // 0..=31
    pub function: u8, // 0..=7
}

impl core::fmt::Display for Location {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:x}",
            self.bus, self.device, self.function
        )
    }
}

/// Identity and classification of one function, decoded from config space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub location: Location,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision: u8,
    pub header_type: u8,
}

impl core::fmt::Display for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} {:04x}:{:04x} class {:02x}{:02x}",
            self.location, self.vendor_id, self.device_id, self.class, self.subclass
        )
    }
}

/// Configuration address (I/O port CF8) selecting dword `offset` of one
/// function. Per the PCI spec the low two bits of `offset` are forced to
/// 0 (dword granularity); out-of-range device/function fields are masked
/// rather than panicking — this value goes straight into a hardware
/// register.
pub fn config_address(loc: Location, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(loc.bus) << 16)
        | ((u32::from(loc.device) & 0x1F) << 11)
        | ((u32::from(loc.function) & 0x07) << 8)
        | u32::from(offset & 0xFC)
}

/// Vendor ID (config offset 0x00, low word).
pub fn vendor_id(id_word: u32) -> u16 {
    id_word as u16
}

/// Device ID (config offset 0x00, high word).
pub fn device_id(id_word: u32) -> u16 {
    (id_word >> 16) as u16
}

/// Class code (config offset 0x0B).
pub fn class_code(class_word: u32) -> u8 {
    (class_word >> 24) as u8
}

/// Subclass (config offset 0x0A).
pub fn subclass(class_word: u32) -> u8 {
    (class_word >> 16) as u8
}

/// Programming interface (config offset 0x09).
pub fn prog_if(class_word: u32) -> u8 {
    (class_word >> 8) as u8
}

/// Revision ID (config offset 0x08).
pub fn revision(class_word: u32) -> u8 {
    class_word as u8
}

/// Header type (config offset 0x0E); bit 7 = multi-function device.
pub fn header_type(header_word: u32) -> u8 {
    (header_word >> 16) as u8
}

/// Bit 7 of the header type: the device has functions beyond 0.
pub fn is_multifunction(header_type: u8) -> bool {
    header_type & 0x80 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn config_address_minimal() {
        let loc = Location {
            bus: 0,
            device: 0,
            function: 0,
        };
        assert_eq!(config_address(loc, 0), 0x8000_0000);
    }

    #[test]
    fn config_address_field_layout() {
        // bus=1 (bits 16..23), device=2 (bits 11..15), function=3
        // (bits 8..10), offset=0x10 (bits 2..7), enable bit 31.
        let loc = Location {
            bus: 1,
            device: 2,
            function: 3,
        };
        assert_eq!(config_address(loc, 0x10), 0x8001_1310);
    }

    #[test]
    fn config_address_masks_offset_and_bad_fields() {
        // Offset is dword-granular: 0x07 → 0x04 (bits 0..1 cleared).
        let loc = Location {
            bus: 0,
            device: 0,
            function: 0,
        };
        assert_eq!(config_address(loc, 0x07), 0x8000_0004);
        // Out-of-range device (32+) and function (8+) are masked, never
        // allowed to bleed into neighbouring fields or panic.
        let bad = Location {
            bus: 0,
            device: 0xFF,
            function: 0xFF,
        };
        assert_eq!(config_address(bad, 0), 0x8000_FF00); // dev 31, fn 7
    }

    #[test]
    fn id_word_fields() {
        let word = 0x1234_5678;
        assert_eq!(vendor_id(word), 0x5678);
        assert_eq!(device_id(word), 0x1234);
        assert_eq!(NO_DEVICE_VENDOR, 0xFFFF);
    }

    #[test]
    fn class_word_fields() {
        // offset 8: revision=0x01, prog_if=0xEF, subclass=0xCD, class=0xAB
        let word = 0xAB_CD_EF_01;
        assert_eq!(class_code(word), 0xAB);
        assert_eq!(subclass(word), 0xCD);
        assert_eq!(prog_if(word), 0xEF);
        assert_eq!(revision(word), 0x01);
    }

    #[test]
    fn header_word_fields() {
        // offset 0x0C: header type lives at byte 2 (bits 16..23).
        let multifunction = 0x0080_0000;
        assert_eq!(header_type(multifunction), 0x80);
        assert!(is_multifunction(header_type(multifunction)));
        assert!(!is_multifunction(header_type(0x0000_0000)));
    }

    #[test]
    fn display_formats() {
        let loc = Location {
            bus: 0x1A,
            device: 0x0B,
            function: 0x02,
        };
        assert_eq!(loc.to_string(), "1a:0b.2");
        let dev = Device {
            location: loc,
            vendor_id: MARVELL_VENDOR,
            device_id: SKY2_88E8053,
            class: 0x02,
            subclass: 0x00,
            prog_if: 0x00,
            revision: 0x11,
            header_type: 0x00,
        };
        assert_eq!(dev.to_string(), "1a:0b.2 11ab:4362 class 0200");
        assert!(is_sky2_target(MARVELL_VENDOR, SKY2_88E8053));
        assert!(!is_sky2_target(0x8086, 0x1237)); // QEMU host bridge
    }

    #[test]
    fn mem_bar_decoding() {
        // I/O-space BAR (bit0 set) → rejected.
        assert_eq!(mem_bar_address(0x0000_C001, 0), None);
        // Unassigned memory BAR → rejected.
        assert_eq!(mem_bar_address(0, 0), None);
        // 32-bit memory BAR: flags in low 4 bits are masked off.
        assert_eq!(mem_bar_address(0xFEB8_0000, 0xDEAD_BEEF), Some(0xFEB8_0000));
        // Prefetchable flag (bit3) also masked.
        assert_eq!(mem_bar_address(0xFEB8_0008, 0), Some(0xFEB8_0000));
        // 64-bit memory BAR (bits2:1 == 0b10): high dword joins in.
        assert_eq!(
            mem_bar_address(0xFEB8_0004, 0x0000_0001),
            Some(0x0000_0001_FEB8_0000)
        );
    }

    #[test]
    fn command_bits_and_ids() {
        assert_eq!(CMD_MEMORY_SPACE, 0x2);
        assert_eq!(CMD_BUS_MASTER, 0x4);
        assert_eq!(INTEL_VENDOR, 0x8086);
        assert_eq!(E1000_82540EM, 0x100E);
    }
}
