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
}
