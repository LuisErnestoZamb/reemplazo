//! MC146818 CMOS real-time clock: raw register reads over ports
//! 0x70/0x71, handed to the host-tested `rtc` crate for decoding.
//!
//! The reading is only as good as the clock: a dead battery or an
//! implausible century makes [`now_epoch`] return `None`, and callers
//! must treat that as "no clock" — TLS then skips certificate *dates*
//! (still enforcing chain, hostname and signatures; see `crate::tls`)
//! rather than trusting a wrong time.

use crate::port::{inb, outb};

// Re-exported so `crate::rtc` is the single time entry point: the
// local module name shadows the extern crate in `main.rs`'s scope.
pub(crate) use ::rtc::from_epoch;

/// CMOS index/data register pair (IBM PC AT standard: QEMU's `pc` and
/// the MacBook's ICH7 both expose them here).
const INDEX: u16 = 0x70;
const DATA: u16 = 0x71;

const REG_A: u8 = 0x0A;
const REG_B: u8 = 0x0B;
/// Status A bit 7: an update is in progress — registers are unstable
/// while it is set.
const UIP: u8 = 0x80;

/// Register addresses read for one time reading (layout documented in
/// the `rtc` crate).
const REG_SECOND: u8 = 0x00;
const REG_MINUTE: u8 = 0x02;
const REG_HOUR: u8 = 0x04;
const REG_DAY: u8 = 0x07;
const REG_MONTH: u8 = 0x08;
const REG_YEAR: u8 = 0x09;
/// Systems disagree on where the century lives: QEMU/Windows convention
/// is 0x32, ACPI-era firmware sometimes uses 0x48. Candidates are tried
/// in order and the first that yields a plausible 20xx year wins (the
/// `rtc` crate rejects anything else).
const REG_CENTURY_CANDIDATES: [u8; 2] = [0x32, 0x48];

/// Bounded wait for the UIP flag: an update cycle is ~244 µs, so a
/// generous spin budget covers a stuck flag without hanging boot.
const UIP_SPINS: u32 = 1_000_000;

/// Current UTC epoch seconds, or `None` when the clock is unavailable
/// (UIP never clears, a register decodes to garbage, or the century
/// does not name a plausible year).
pub fn now_epoch() -> Option<u64> {
    // Wait until the clock is between updates so the registers read
    // as one consistent snapshot.
    let mut spins = 0;
    while cmos_read(REG_A) & UIP != 0 {
        spins += 1;
        if spins > UIP_SPINS {
            return None; // stuck updating: no clock, never a guess
        }
        core::hint::spin_loop();
    }

    let status_b = cmos_read(REG_B);
    // DM (bit 2): 0 = BCD digits (default), 1 = binary. 24HR (bit 1):
    // 1 = 24-hour mode — inverted sense, decoded and host-tested by
    // `rtc::status_flags`.
    let flags = rtc::status_flags(status_b);
    let hour = cmos_read(REG_HOUR);

    let common = |century: u8| rtc::RawClock {
        second: cmos_read(REG_SECOND),
        minute: cmos_read(REG_MINUTE),
        hour,
        day: cmos_read(REG_DAY),
        month: cmos_read(REG_MONTH),
        year: cmos_read(REG_YEAR),
        century,
        binary: flags.binary,
        hour12: flags.hour12,
    };

    for reg in REG_CENTURY_CANDIDATES {
        let raw = common(cmos_read(reg));
        if let Ok(clock) = rtc::decode(&raw) {
            return Some(rtc::to_epoch(&clock));
        }
    }
    None // no candidate names a plausible year: "no clock"
}

/// One CMOS register read.
///
/// Bit 7 of the index port masks NMI; writing `reg & 0x7F` leaves the
/// NMI mask as it was (enabled).
///
/// # Safety
/// Ports 0x70/0x71 are the standard CMOS pair on every machine we
/// target (verified working under Debian on the MacBook and in QEMU).
#[inline]
fn cmos_read(reg: u8) -> u8 {
    // SAFETY: see above — valid, standard I/O ports; the access width
    // (byte) matches the device contract.
    unsafe {
        outb(INDEX, reg & 0x7F);
        inb(DATA)
    }
}
