//! CRC-32 (ISO 3309 / ITU-T V.42, the CRC GPT mandates for its header
//! and partition-entry array) — bitwise, no table.
//!
//! The algorithm is the standard reflected CRC-32 with polynomial
//! `0xEDB8_8320` (the reversed form of `0x04C1_1DB7`), initial value
//! `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`. Correctness is pinned by the
//! classic check value in `tests/hostile.rs` (`"123456789"` →
//! `0xCBF4_3926`), so this implementation cannot drift silently.
//!
//! Why bitwise instead of a 256-entry table: the largest thing this
//! ever checksums is the 16 KiB entry array (131072 bit iterations —
//! microseconds), and a table would be 1 KiB of `.rodata` in the kernel
//! for no measurable gain on a Core2. `docs/installer.md` §3.2 already
//! budgets this as "~20-line table-driven CRC32" glue.

/// Streaming CRC-32: [`update`](Crc32::update) any number of chunks,
/// then [`finish`](Crc32::finish) once.
#[derive(Clone, Copy)]
pub struct Crc32(u32);

impl Crc32 {
    pub(crate) fn new() -> Self {
        Self(0xFFFF_FFFF)
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 ^= u32::from(b);
            for _ in 0..8 {
                // Mask = 0xFFFF_FFFF when the low bit is set, 0
                // otherwise — branch-free conditional XOR (the classic
                // reflected-CRC step).
                let mask = (self.0 & 1).wrapping_neg();
                self.0 = (self.0 >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
    }

    pub(crate) fn finish(self) -> u32 {
        self.0 ^ 0xFFFF_FFFF
    }
}

/// One-shot CRC-32 over `bytes`. Public because GPT's header CRC is
/// part of the on-disk format other tools implement too, and the
/// hostile tests use it to *recompute* a valid CRC after corrupting a
/// header — which is how "bad CRC" and "CRC field patched to match
/// garbage" are told apart.
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = Crc32::new();
    crc.update(bytes);
    crc.finish()
}
