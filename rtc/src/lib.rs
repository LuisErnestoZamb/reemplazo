//! Pure decoding of MC146818 CMOS real-time-clock register bytes into
//! a UTC epoch timestamp. No I/O lives here: the kernel reads ports
//! 0x70/0x71 and calls [`decode`]/[`to_epoch`]; every branch — BCD
//! digits, 12/24-hour format, leap years, the century plausibility
//! bound — is host-tested with adversarial inputs (skill rule: pure
//! parsers get adversarial tests).

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// A validated clock reading in UTC (the CMOS holds no timezone).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Clock {
    /// Full year; [`decode`] accepts only 2000..=2099 (see there).
    pub year: u16,
    /// 1..=12
    pub month: u8,
    /// 1..=31, valid for `month`/`year`
    pub day: u8,
    /// 0..=23 (always normalized to 24-hour, even from 12-hour mode)
    pub hour: u8,
    /// 0..=59
    pub minute: u8,
    /// 0..=59
    pub second: u8,
}

/// Why a reading was rejected. Every error is fail-closed: a rejected
/// reading means "no clock", never "wrong-but-plausible time".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A BCD nibble held a digit greater than 9 (garbage register).
    BadBcd,
    /// A field was outside its legal range (month 13, hour 24, …).
    BadRange,
    /// The day does not exist in that month/year (Feb 30, or Feb 29
    /// on a non-leap year).
    BadDay,
    /// The century produced a year outside 2000..=2099 — implausible
    /// for this device, so treated as "no clock" rather than trusted
    /// (a dead CMOS battery reads 1990s, which must not silently pass
    /// certificate-date checks).
    BadCentury,
}

/// Raw register bytes plus the status-B format flags, as the kernel
/// read them (MC146818 layout: seconds 0x00, minutes 0x02, hours
/// 0x04, day 0x07, month 0x08, year 0x09, century 0x32/0x48).
#[derive(Debug, Clone, Copy)]
pub struct RawClock {
    pub second: u8,
    pub minute: u8,
    /// Hours register; bit 7 is the PM flag in 12-hour mode.
    pub hour: u8,
    pub day: u8,
    pub month: u8,
    /// Two-digit year (26 → 2026 with century 20).
    pub year: u8,
    /// Two-digit century from the CMOS century register (20 → 20xx).
    pub century: u8,
    /// Status B bit 2 (DM): `false` = BCD digits (the CMOS default),
    /// `true` = binary.
    pub binary: bool,
    /// Status B bit 1 (12/24): `true` = 12-hour mode (hour bit 7 is
    /// then the PM flag), `false` = 24-hour mode.
    pub hour12: bool,
}

impl RawClock {
    /// The PM flag carried in bit 7 of the raw hours register.
    fn pm(&self) -> bool {
        self.hour & 0x80 != 0
    }
}

/// Decode and validate a raw reading.
///
/// The full year must land in 2000..=2099: the century register is
/// the least trustworthy byte (systems disagree on which CMOS address
/// holds it), so a reading that names any other century is refused
/// instead of guessed — [`crate`]'s callers then report "no clock".
pub fn decode(raw: &RawClock) -> Result<Clock, Error> {
    let second = field(raw.second, raw.binary)?;
    let minute = field(raw.minute, raw.binary)?;
    if second > 59 || minute > 59 {
        return Err(Error::BadRange);
    }

    // Strip the PM flag before decoding; in 24-hour mode it is
    // reserved and must not corrupt the digits.
    let hour = field(raw.hour & 0x7F, raw.binary)?;
    let hour = if raw.hour12 {
        if !(1..=12).contains(&hour) {
            return Err(Error::BadRange);
        }
        hour % 12 + if raw.pm() { 12 } else { 0 }
    } else if hour > 23 {
        return Err(Error::BadRange);
    } else {
        hour
    };

    let month = field(raw.month, raw.binary)?;
    let day = field(raw.day, raw.binary)?;
    let year2 = field(raw.year, raw.binary)?;
    let century = field(raw.century, raw.binary)?;
    let year = u16::from(century) * 100 + u16::from(year2);
    if !(2000..=2099).contains(&year) {
        return Err(Error::BadCentury);
    }
    if !(1..=12).contains(&month) {
        return Err(Error::BadRange);
    }
    if !(1..=31).contains(&day) {
        return Err(Error::BadRange);
    }
    if day > days_in_month(year, month).ok_or(Error::BadRange)? {
        return Err(Error::BadDay);
    }

    Ok(Clock {
        year,
        month,
        day,
        hour,
        minute,
        second,
    })
}

/// Interpret one register byte as binary or BCD, rejecting BCD with a
/// non-digit nibble.
fn field(raw: u8, binary: bool) -> Result<u8, Error> {
    if binary {
        Ok(raw)
    } else {
        let (hi, lo) = (raw >> 4, raw & 0x0F);
        if hi > 9 || lo > 9 {
            Err(Error::BadBcd)
        } else {
            Ok(hi * 10 + lo)
        }
    }
}

/// Gregorian leap-year rule (divisible by 4, except centuries —
/// unless divisible by 400).
pub fn is_leap(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Days in `month` of `year`; `None` when the month itself is invalid.
pub fn days_in_month(year: u16, month: u8) -> Option<u8> {
    Some(match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap(year) => 29,
        2 => 28,
        _ => return None,
    })
}

/// Seconds since 1970-01-01T00:00:00Z for a validated reading.
pub fn to_epoch(c: &Clock) -> u64 {
    let days = days_from_civil(i64::from(c.year), c.month, c.day);
    days as u64 * 86_400
        + u64::from(c.hour) * 3_600
        + u64::from(c.minute) * 60
        + u64::from(c.second)
}

/// Inverse of [`to_epoch`]: the UTC parts of an epoch timestamp.
///
/// Only meaningful for epochs that decode into a year that fits `u16`
/// — callers pass timestamps from [`to_epoch`]-range readings.
pub fn from_epoch(epoch: u64) -> Clock {
    let (year, month, day) = civil_from_days((epoch / 86_400) as i64);
    let secs = epoch % 86_400;
    Clock {
        year: year as u16,
        month,
        day,
        hour: (secs / 3_600) as u8,
        minute: ((secs % 3_600) / 60) as u8,
        second: (secs % 60) as u8,
    }
}

/// Days since 1970-01-01 for a civil date (Howard Hinnant's
/// `days_from_civil`: era-based, no drift over the Gregorian cycle).
fn days_from_civil(y: i64, m: u8, d: u8) -> i64 {
    let y = y - i64::from(m <= 2); // move Jan/Feb into the previous year
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let doy = (153 * u64::from(if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// Inverse of [`days_from_civil`].
fn civil_from_days(z: i64) -> (i64, u8, u8) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]: 0 = March
    let day = (doy - (153 * mp + 2) / 5 + 1) as u8; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u8; // [1, 12]
    (y + i64::from(month <= 2), month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid BCD reading: 2026-11-21 12:34:56 (12-hour, PM).
    fn noon_2026() -> RawClock {
        RawClock {
            second: 0x56,  // BCD 56
            minute: 0x34,  // BCD 34
            hour: 0x92,    // BCD 12 | PM flag
            day: 0x21,     // BCD 21
            month: 0x11,   // BCD 11
            year: 0x26,    // BCD 26
            century: 0x20, // BCD 20
            binary: false,
            hour12: true,
        }
    }

    #[test]
    fn bcd_noon_decodes_and_epochs() {
        let c = decode(&noon_2026()).expect("valid reading");
        assert_eq!(
            c,
            Clock {
                year: 2026,
                month: 11,
                day: 21,
                hour: 12,
                minute: 34,
                second: 56
            }
        );
        assert_eq!(to_epoch(&c), 1_795_264_496);
    }

    #[test]
    fn known_epoch_values() {
        assert_eq!(
            to_epoch(&Clock {
                year: 2000,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }),
            946_684_800
        );
        assert_eq!(
            to_epoch(&Clock {
                year: 2024,
                month: 2,
                day: 29,
                hour: 0,
                minute: 0,
                second: 0
            }),
            1_709_164_800
        );
        assert_eq!(
            to_epoch(&Clock {
                year: 1970,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0
            }),
            0
        );
    }

    #[test]
    fn epoch_roundtrip() {
        for epoch in [0, 946_684_800, 1_709_164_800, 1_795_264_496, 1_795_264_495] {
            assert_eq!(to_epoch(&from_epoch(epoch)), epoch, "epoch {epoch}");
        }
    }

    #[test]
    fn twelve_hour_normalization() {
        let at = |hour_bcd: u8, pm: bool| {
            let mut raw = noon_2026();
            raw.hour = hour_bcd | if pm { 0x80 } else { 0 };
            decode(&raw).expect("valid").hour
        };
        assert_eq!(at(0x12, false), 0); // 12 AM → 00
        assert_eq!(at(0x12, true), 12); // 12 PM → 12
        assert_eq!(at(0x11, true), 23); // 11 PM → 23
        assert_eq!(at(0x01, false), 1); // 1 AM → 01
        assert_eq!(at(0x01, true), 13); // 1 PM → 13
    }

    #[test]
    fn twelve_hour_rejects_out_of_range_digits() {
        let mut raw = noon_2026();
        raw.hour = 0x13; // 13 o'clock does not exist in 12-hour mode
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw.hour = 0x00; // nor does 0
        assert_eq!(decode(&raw), Err(Error::BadRange));
    }

    #[test]
    fn twenty_four_hour_mode_and_pm_flag_stripped() {
        let mut raw = noon_2026();
        raw.hour12 = false;
        raw.hour = 0x92; // PM bit set in 24-hour mode: must be ignored
        assert_eq!(decode(&raw).expect("valid").hour, 12);
        raw.hour = 0x24; // BCD 24
        assert_eq!(decode(&raw), Err(Error::BadRange));
        // Switch the whole reading to binary encoding (one flag
        // applies to every register), then hour 23 is legal…
        raw.binary = true;
        raw.hour12 = false;
        raw.hour = 23;
        raw.second = 56;
        raw.minute = 34;
        raw.day = 21;
        raw.month = 11;
        raw.year = 26;
        raw.century = 20;
        assert_eq!(decode(&raw).expect("valid").hour, 23);
        raw.hour = 24;
        assert_eq!(decode(&raw), Err(Error::BadRange));
    }

    #[test]
    fn bcd_non_digit_nibbles_are_rejected() {
        let mut raw = noon_2026();
        raw.minute = 0x1A; // units nibble A is not a digit
        assert_eq!(decode(&raw), Err(Error::BadBcd));
        raw = noon_2026();
        raw.century = 0x2F;
        assert_eq!(decode(&raw), Err(Error::BadBcd));
        raw = noon_2026();
        raw.second = 0xA5;
        assert_eq!(decode(&raw), Err(Error::BadBcd));
    }

    #[test]
    fn binary_mode_decodes_raw_values() {
        let raw = RawClock {
            second: 56,
            minute: 34,
            hour: 12,
            day: 21,
            month: 11,
            year: 26,
            century: 20,
            binary: true,
            hour12: false,
        };
        assert_eq!(
            decode(&raw),
            Ok(Clock {
                year: 2026,
                month: 11,
                day: 21,
                hour: 12,
                minute: 34,
                second: 56
            })
        );
    }

    #[test]
    fn field_ranges_are_enforced() {
        let mut raw = noon_2026();
        raw.month = 0x00;
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw = noon_2026();
        raw.month = 0x13; // BCD 13
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw = noon_2026();
        raw.day = 0x00;
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw = noon_2026();
        raw.day = 0x32; // BCD 32
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw = noon_2026();
        raw.minute = 60;
        raw.binary = true;
        raw.hour12 = false;
        assert_eq!(decode(&raw), Err(Error::BadRange));
        raw = noon_2026();
        raw.second = 0x60; // BCD 60 (leap second): refused
        assert_eq!(decode(&raw), Err(Error::BadRange));
    }

    #[test]
    fn february_day_validity() {
        // 2026 is not a leap year: Feb 29 must not exist…
        let mut raw = noon_2026();
        raw.month = 0x02;
        raw.day = 0x29;
        assert_eq!(decode(&raw), Err(Error::BadDay));
        raw.day = 0x30;
        assert_eq!(decode(&raw), Err(Error::BadDay));
        // …but Feb 29 2024 (leap) and Feb 29 2000 (÷400 leap) do.
        raw = noon_2026();
        raw.month = 0x02;
        raw.day = 0x29;
        raw.year = 0x24;
        assert_eq!(decode(&raw).expect("leap year").day, 29);
        raw.year = 0x00; // 2000: divisible by 400 → leap
        assert_eq!(decode(&raw).expect("400-year leap").day, 29);
        raw.year = 0x26;
        raw.day = 0x31;
        assert_eq!(decode(&raw), Err(Error::BadDay)); // Feb 31
    }

    #[test]
    fn century_plausibility_bounds() {
        for century in [0x00, 0x19, 0x21, 0x99] {
            let mut raw = noon_2026();
            raw.century = century;
            assert_eq!(decode(&raw), Err(Error::BadCentury), "century {century:#x}");
        }
    }

    #[test]
    fn days_in_month_table_and_leap_rules() {
        assert_eq!(days_in_month(2026, 1), Some(31));
        assert_eq!(days_in_month(2026, 4), Some(30));
        assert_eq!(days_in_month(2026, 2), Some(28));
        assert_eq!(days_in_month(2024, 2), Some(29));
        assert_eq!(days_in_month(2000, 2), Some(29)); // ÷400
        assert_eq!(days_in_month(1900, 2), Some(28)); // century, not ÷400
        assert_eq!(days_in_month(2100, 2), Some(28)); // century, not ÷400
        assert_eq!(days_in_month(2026, 0), None);
        assert_eq!(days_in_month(2026, 13), None);
        assert!(!is_leap(2026));
        assert!(is_leap(2024));
        assert!(is_leap(2000));
        assert!(!is_leap(1900));
    }

    #[test]
    fn from_epoch_handles_year_boundaries() {
        // 1999-12-31 23:59:59 → 946_684_799 (just before 2000).
        let c = from_epoch(946_684_799);
        assert_eq!(
            (c.year, c.month, c.day, c.hour, c.minute, c.second),
            (1999, 12, 31, 23, 59, 59)
        );
        // Leap-day midnight.
        let c = from_epoch(1_709_164_800);
        assert_eq!((c.year, c.month, c.day), (2024, 2, 29));
    }
}
