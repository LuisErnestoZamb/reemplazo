//! ICH7 SMBus host controller — the bus where the MacBook's Apple SMC
//! (fans, temperature, battery) lives.
//!
//! `00:1f.3 SMBus [0c05] 8086:27da`. register map (ICH7 datasheet §13):
//!
//! | offset | register |
//! |---|---|
//! | +0 | SMBHSTSTS (write 0xFF clears) |
//! | +2 | SMBHSTCNT (bit 6 START, bits 3..4 protocol) |
//! | +3 | SMBHSTCMD |
//! | +4 | SMBHSTADD (7-bit address << 1, bit0 = R/W) |
//! | +5 | SMBHSTDAT0 |
//! | +6 | SMBHSTDAT1 |
//!
//! Everything is bounded: a stuck bus becomes "device absent", never a
//! hung boot. The driver is silent when the controller is missing
//! (every QEMU smoke), so the marker chains stay untouched.

use crate::pci::Scan;
use crate::port::{inb, outb};

const ICH7_SMBUS: (u16, u16) = (0x8086, 0x27DA);
const POLL_LIMIT: u32 = 2_000_000;
const STS_BUSY: u8 = 0x01;
const STS_ERR: u8 = 0x1C;
const CNT_START: u8 = 0x40;
const PROTOCOL_QUICK: u8 = 0x04;
const PROTOCOL_BYTE: u8 = 0x08;

pub(crate) struct Smbus {
    base: u16,
}

/// Wait for the controller to actually assert BUSY after START. Without
/// this step every address looks successful: reading status too early
/// sees BUSY=0 and an error-free byte, which produced 111 fake devices
/// on the first hardware run.
fn wait_start(base: u16) -> bool {
    let mut spins = 0u32;
    loop {
        // SAFETY: see `transact` — BAR-validated I/O port.
        let st = unsafe { inb(base) };
        if st & STS_BUSY != 0 {
            return true;
        }
        spins += 1;
        if spins > POLL_LIMIT {
            return false;
        }
        core::hint::spin_loop();
    }
}

fn wait_done(base: u16) -> Option<u8> {
    let mut spins = 0u32;
    loop {
        // SAFETY: see `transact`.
        let st = unsafe { inb(base) };
        if st & STS_BUSY == 0 {
            return if st & STS_ERR != 0 { None } else { Some(st) };
        }
        spins += 1;
        if spins > POLL_LIMIT {
            return None;
        }
        core::hint::spin_loop();
    }
}

impl Smbus {
    fn transact(&self, addr: u8, cmd: u8, read: bool, protocol: u8) -> Option<u8> {
        // SAFETY: validated BAR, byte-wide I/O, bounded polls.
        unsafe {
            outb(self.base, 0xFF); // clear sticky status bits
            outb(self.base + 4, (addr << 1) | u8::from(read));
            outb(self.base + 3, cmd);
            outb(self.base + 2, protocol | CNT_START);
        }
        if !wait_start(self.base) {
            return None;
        }
        let st = wait_done(self.base)?;
        // SAFETY: see `transact`.
        let data = unsafe { inb(self.base + 5) };
        let _ = st;
        Some(data)
    }

    /// SMBus quick write: the cheapest "is anybody at this address?"
    /// probe. A NAK shows up as a status error, not a hang.
    fn present(&self, addr: u8) -> bool {
        // SAFETY: see `transact`.
        unsafe {
            outb(self.base, 0xFF);
            outb(self.base + 4, addr << 1);
            outb(self.base + 2, PROTOCOL_QUICK | CNT_START);
        }
        wait_start(self.base) && wait_done(self.base).is_some()
    }

    fn read_byte(&self, addr: u8, cmd: u8) -> Option<u8> {
        self.transact(addr, cmd, true, PROTOCOL_BYTE)
    }
}

/// Probe the controller, then record the 7-bit devices that answer.
/// Returns `false` when absent so the aggregator can mark it "not found".
pub(crate) fn probe(scan: &Scan) -> bool {
    let Some(dev) = scan.find(ICH7_SMBUS.0, ICH7_SMBUS.1) else {
        return false;
    };
    // Enable I/O decode + bus master (firmware usually already did).
    let command = crate::pci::read32(dev.location, 0x04);
    crate::pci::write32(dev.location, 0x04, command | 0x05);

    // ICH7 exposes the SMBus base in config offset 0x20 as an I/O BAR.
    let smba = crate::pci::read32(dev.location, 0x20);
    if smba & 1 == 0 {
        return false;
    }
    let base = (smba & 0xFFE0) as u16;
    if base == 0 {
        return false;
    }
    let bus = Smbus { base };
    serial_println!("smbus: ICH7 at {:#x}", base);

    let mut found = 0usize;
    for addr in 0x08u8..=0x77 {
        if bus.present(addr) {
            serial_println!("smbus: device at 0x{:02X}", addr);
            let line = alloc::format!("smbus device 0x{addr:02X} answered");
            let mut tag = [0u8; 112];
            let n = line.len().min(tag.len());
            tag[..n].copy_from_slice(&line.as_bytes()[..n]);
            crate::logdisk::log(0xE4, &tag[..n]);
            found += 1;
        }
    }
    // A read of the SMC's "fan number" register (0x30 on Apple SMC)
    // from the usual 0x10 address, recorded only when it answers.
    if bus.present(0x10)
        && let Some(n) = bus.read_byte(0x10, 0x30)
    {
        let line = alloc::format!("smc 0x10 fan-count byte={n:#x}");
        let mut tag = [0u8; 112];
        let len = line.len().min(tag.len());
        tag[..len].copy_from_slice(&line.as_bytes()[..len]);
        crate::logdisk::log(0xE5, &tag[..len]);
    }
    serial_println!("smbus: {found} devices answered");
    let line = alloc::format!("smbus: {found} devices on 0x{base:x}");
    crate::logdisk::log(0xE6, line.as_bytes());
    true
}
