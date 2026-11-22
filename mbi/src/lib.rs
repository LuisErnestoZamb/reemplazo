//! Range pre-checks for the bootloader-supplied Multiboot2 information
//! (MBI) structure — the kernel's safety contract before it hands the raw
//! pointer to `multiboot2::BootInformation::load`.
//!
//! The crate's `load` takes a *pointer*, not a slice: it has no buffer
//! length and trusts the caller that `addr..addr+total_size` is valid,
//! readable, identity-mapped memory. These checks are the only thing
//! enforcing that contract on our side (GRUB data is untrusted), so they
//! are pure arithmetic, `forbid(unsafe_code)` and host-tested here —
//! together with adversarial inputs to the crate's own parser
//! (`tests/hostile.rs`).
//!
//! What moved upstream with the `multiboot2` swap: the tag-sequence walk
//! (truncated tags, `size < 8`, missing end tag) — validated by the crate
//! within the declared `total_size`. What could *not* move: "declared
//! `total_size` ≤ the real buffer length", which a pointer API cannot
//! check; that stays this crate's job, bounded by [`MBI_MAX_BYTES`].
//!
//! [`check_module`] covers the other bootloader pointer the kernel
//! dereferences: a module tag's `mod_start..mod_end` byte range
//! (tag type 3, §3.6.4), capped by its *consumer* (the installer's
//! 1 MiB `bios_grub` partition for GRUB's artifacts, the download bound
//! for the kernel payload).

#![no_std]
#![forbid(unsafe_code)]

/// Highest `total_size` we'll read from a bootloader-supplied structure.
/// Real Multiboot2 info is a few KiB; 1 MiB is a generous sanity bound
/// that keeps the crate's pointer-based reads inside a known range.
pub const MBI_MAX_BYTES: usize = 1 << 20;

/// Why the handoff range was rejected (printed via `{:?}` on the kernel's
/// `FATAL: bad multiboot2 info` line).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `addr` is 0 or above the 4 GiB identity map. Unreachable by GRUB
    /// (EBX is 32-bit) — treat as invalid anyway.
    BadAddress { addr: u64 },
    /// `total_size` is outside `8..=MBI_MAX_BYTES`. Checked before any
    /// slice or pointer over the structure is built.
    BadTotalSize { total: usize },
    /// `addr + total_size` would cross the end of the 4 GiB identity map
    /// (the `checked_add` also folds `u64` overflow into this variant).
    CrossesMap { addr: u64, total: usize },
}

/// Check the handoff address alone. Must pass *before* the 4-byte
/// `total_size` read at `addr` (see `kernel/src/main.rs::read_mbi`).
pub fn check_addr(addr: u64) -> Result<(), RangeError> {
    if addr == 0 || addr > 0xFFFF_FFFF {
        return Err(RangeError::BadAddress { addr });
    }
    Ok(())
}

/// The full range contract, in the order `read_mbi` applies it: address
/// inside the identity map, `total_size` a sane length, whole structure
/// inside the map — all before any pointer over it is built.
pub fn check_range(addr: u64, total: usize) -> Result<(), RangeError> {
    check_addr(addr)?;
    if !(8..=MBI_MAX_BYTES).contains(&total) {
        return Err(RangeError::BadTotalSize { total });
    }
    if addr
        .checked_add(total as u64)
        .is_none_or(|end| end > 0x1_0000_0000)
    {
        return Err(RangeError::CrossesMap { addr, total });
    }
    Ok(())
}

/// Why a boot-module range was rejected (`FATAL: mbi:` in the kernel —
/// modules are only dereferenced when the installer needs their bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModuleError {
    /// `mod_start == 0`: address zero is never a valid module (it is
    /// reserved low memory, and a zero start usually means a malformed
    /// tag).
    NullStart,
    /// `mod_end == mod_start`: the tag describes an empty blob. GRUB
    /// never emits this for a real module file, so treat it as invalid.
    Empty { start: u32, end: u32 },
    /// `mod_end < mod_start`: the only way this happens is a corrupt or
    /// hostile tag (the `multiboot2` crate exposes both halves verbatim
    /// and its `module_size()` asserts on this case).
    Reversed { start: u32, end: u32 },
    /// The blob is bigger than the caller's hard cap. Callers pick a cap
    /// from the *consumer* (the 1 MiB `bios_grub` partition for GRUB's
    /// artifacts, the download bound for a kernel payload), never from
    /// the tag.
    TooLarge { len: usize, cap: usize },
}

/// Validate one Multiboot2 **module tag** range (tag type 3, §3.6.4) and
/// return its byte length.
///
/// The tag holds two 32-bit physical addresses; the kernel dereferences
/// the range as a byte slice, so this is the whole safety contract, in
/// the same spirit as [`check_range`] for the MBI itself:
///
/// - `start != 0`, because zero is never a module and a zero start is a
///   corrupt tag;
/// - `end > start` (the crate's own `module_size()` panics on the
///   reverse; we refuse instead);
/// - the length fits the caller's hard `cap` — a size derived from the
///   consumer, so a hostile bootloader cannot make us copy or read an
///   unbounded blob;
/// - both halves are `u32`, so the range is inside the first 4 GiB,
///   i.e. inside `entry.S`'s identity map by construction.
///
/// Dependencies: none, pure arithmetic — host-tested with adversarial
/// ranges below.
pub fn check_module(start: u32, end: u32, cap: usize) -> Result<usize, ModuleError> {
    if start == 0 {
        return Err(ModuleError::NullStart);
    }
    let len = match end.cmp(&start) {
        core::cmp::Ordering::Less => return Err(ModuleError::Reversed { start, end }),
        core::cmp::Ordering::Equal => return Err(ModuleError::Empty { start, end }),
        core::cmp::Ordering::Greater => (end - start) as usize,
    };
    if len > cap {
        return Err(ModuleError::TooLarge { len, cap });
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// GRUB's usual MBI location (just above 1 MiB).
    const LOW: u64 = 0x10_0000;

    #[test]
    fn accepts_a_sane_handoff() {
        assert_eq!(check_addr(LOW), Ok(()));
        // inclusive bounds on both sides
        assert_eq!(check_range(LOW, 8), Ok(()));
        assert_eq!(check_range(LOW, MBI_MAX_BYTES), Ok(()));
        // tightest fit that still ends exactly at the 4 GiB map end
        assert_eq!(check_range(0x1_0000_0000 - 48, 48), Ok(()));
    }

    #[test]
    fn rejects_null_and_out_of_map_addresses() {
        assert_eq!(check_addr(0), Err(RangeError::BadAddress { addr: 0 }));
        // one byte past the identity map
        assert_eq!(
            check_addr(0x1_0000_0000),
            Err(RangeError::BadAddress {
                addr: 0x1_0000_0000
            })
        );
        assert_eq!(
            check_addr(u64::MAX),
            Err(RangeError::BadAddress { addr: u64::MAX })
        );
        // the 4 GiB boundary itself is in-map; the end check rejects it
        assert_eq!(check_addr(0xFFFF_FFFF), Ok(()));
    }

    #[test]
    fn rejects_tiny_or_oversized_total() {
        for total in [0usize, 1, 7, MBI_MAX_BYTES + 1, usize::MAX] {
            assert_eq!(
                check_range(LOW, total),
                Err(RangeError::BadTotalSize { total }),
                "total={total}"
            );
        }
    }

    #[test]
    fn rejects_total_that_crosses_the_identity_map() {
        // starts in-map, ends 4 KiB past it
        assert_eq!(
            check_range(0xFFFF_F000, 0x2000),
            Err(RangeError::CrossesMap {
                addr: 0xFFFF_F000,
                total: 0x2000
            })
        );
        // topmost in-map byte: addr ok, addr+total not
        assert_eq!(
            check_range(0xFFFF_FFFF, 8),
            Err(RangeError::CrossesMap {
                addr: 0xFFFF_FFFF,
                total: 8
            })
        );
    }

    // --- module tags (tag type 3) -------------------------------------

    #[test]
    fn accepts_a_sane_module_range_and_returns_its_length() {
        // 152 KiB GRUB blob just above 1 MiB, a 2 MiB kernel payload
        assert_eq!(check_module(0x10_0000, 0x12_6000, 4 << 20), Ok(0x2_6000));
        assert_eq!(check_module(0x20_0000, 0x40_0000, 2 << 20), Ok(2 << 20));
        // one byte is a legal (if useless) module; the consumer decides
        // whether that is enough
        assert_eq!(check_module(0x1000, 0x1001, 1), Ok(1));
        // the highest representable in-map range
        assert_eq!(check_module(1, 0xFFFF_FFFF, 0xFFFF_FFFE), Ok(0xFFFF_FFFE));
    }

    #[test]
    fn rejects_null_start_before_anything_else() {
        for (start, end) in [(0u32, 0u32), (0, 1), (0, 0xFFFF_FFFF)] {
            assert_eq!(
                check_module(start, end, 1 << 20),
                Err(ModuleError::NullStart),
                "start={start} end={end}"
            );
        }
    }

    #[test]
    fn rejects_empty_and_reversed_ranges() {
        for start in [1u32, 0x1000, 0xFFFF_FFFE, 0xFFFF_FFFF] {
            assert_eq!(
                check_module(start, start, usize::MAX),
                Err(ModuleError::Empty { start, end: start }),
                "start={start}"
            );
        }
        for (start, end) in [
            (2u32, 1u32),
            (0x1000, 0x0FFF),
            (0xFFFF_FFFF, 0),
            (0xFFFF_FFFF, 0xFFFF_FFFE),
        ] {
            // reversal is detected before the cap, whatever the cap is
            assert_eq!(
                check_module(start, end, 1),
                Err(ModuleError::Reversed { start, end }),
                "start={start} end={end}"
            );
        }
    }

    #[test]
    fn enforces_the_callers_cap_exactly() {
        let (start, cap) = (0x10_0000u32, 0x2_6000usize);
        let end = start + cap as u32;
        // exactly at the cap is accepted…
        assert_eq!(check_module(start, end, cap), Ok(cap));
        // …one byte over is refused with both numbers for the log line
        assert_eq!(
            check_module(start, end + 1, cap),
            Err(ModuleError::TooLarge { len: cap + 1, cap })
        );
        // a zero cap cannot accept any real module
        assert_eq!(
            check_module(start, start + 1, 0),
            Err(ModuleError::TooLarge { len: 1, cap: 0 })
        );
    }

    #[test]
    fn a_whole_4gib_module_never_wraps() {
        // start=1, end=u32::MAX: the length is computed in u32 (no
        // overflow), then compared with the cap as usize
        assert_eq!(check_module(1, u32::MAX, usize::MAX), Ok(0xFFFF_FFFE));
        assert_eq!(
            check_module(1, u32::MAX, 0xFFFF_FFFD),
            Err(ModuleError::TooLarge {
                len: 0xFFFF_FFFE,
                cap: 0xFFFF_FFFD
            })
        );
    }
}
