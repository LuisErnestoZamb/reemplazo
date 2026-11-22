//! Transfer geometry: sector counts, per-command chunking, PRDT
//! segmentation and IDENTIFY DEVICE decoding.
//!
//! Sources: ATA8-ACS2 §7.16 "IDENTIFY DEVICE" (word 60 = LBA28 sectors
//! 27:16 / word 61 = 47:32, word 83 bit 10 = 48-bit supported, words
//! 100..103 = maximum LBA48; words 27..46 = model number, "byte
//! swapped" ATA strings) and §4.14 (48-bit addressing); AHCI 1.3.1
//! §4.3 (PRDT byte-count field). The `512`-byte sector is ATA8-ACS2
//! §3.2's logical sector for this device class and what every consumer
//! in this repository (`fat`, `gptwire`, the installer) assumes.

/// Bytes per logical sector (ATA8-ACS2 §3.2; the smoke disks are
/// 512-byte-sector images).
pub const SECTOR_BYTES: usize = 512;

/// One `read_sectors`/`write_sectors` request is bounded to 256 sectors
/// (128 KiB) — the same contract `ata::Drive` documents, so the
/// filesystem, GPT and installer code is source-compatible.
pub const MAX_TRANSFER_SECTORS: u16 = 256;

/// Sectors one AHCI command moves: 128 sectors = 64 KiB = the 16 DMA
/// frames the driver owns ([`DATA_FRAMES`]). A 256-sector request is
/// split into two commands — the arithmetic [`split_request`] proves it
/// loses nothing.
pub const MAX_CMD_SECTORS: u16 = 128;

/// Bytes one command moves.
pub const MAX_CMD_BYTES: usize = MAX_CMD_SECTORS as usize * SECTOR_BYTES;

/// DMA data frames backing one command: the PRDT is built with one
/// entry per frame, so a fragmented physical allocation is still one
/// scatter/gather transfer (no contiguity assumed).
pub const DATA_FRAMES: usize = MAX_CMD_BYTES / crate::FRAME_BYTES;

/// Sector count for a byte-length request: whole, non-empty sectors
/// inside the [`MAX_TRANSFER_SECTORS`] contract.
///
/// This is the *device* boundary, the mirror of `ata::Drive`'s check —
/// a caller that asks for a partial sector or 0 bytes gets `None`, never
/// a silently rounded transfer.
pub fn sectors_for(len: usize) -> Option<u16> {
    if len == 0 || !len.is_multiple_of(SECTOR_BYTES) {
        return None;
    }
    let sectors = len / SECTOR_BYTES;
    if sectors > usize::from(MAX_TRANSFER_SECTORS) {
        return None;
    }
    u16::try_from(sectors).ok()
}

/// Sectors to put in the next command when `remaining` are left.
/// Always `None` only for `remaining == 0`.
pub fn next_chunk(remaining: u16) -> Option<u16> {
    if remaining == 0 {
        return None;
    }
    Some(remaining.min(MAX_CMD_SECTORS))
}

/// Split a transfer into (`lba`, `sectors`) command chunks — the
/// driver's loop, expressed once and host-testable. Fills `out` and
/// returns how many entries were written; `None` when the request
/// violates the contract (`0`, > 256 sectors) or the output cannot hold
/// every chunk.
///
/// For 256 sectors this yields exactly two `(lba, 128)` chunks.
pub fn split_request(lba: u64, sectors: u16, out: &mut [(u64, u16)]) -> Option<usize> {
    if sectors == 0 || sectors > MAX_TRANSFER_SECTORS {
        return None;
    }
    let needed = usize::from(sectors).div_ceil(usize::from(MAX_CMD_SECTORS));
    if out.len() < needed {
        return None;
    }
    let mut left = sectors;
    let mut at = lba;
    for slot in out.iter_mut().take(needed) {
        let take = next_chunk(left)?;
        *slot = (at, take);
        at = at.checked_add(u64::from(take))?;
        left -= take;
    }
    (left == 0).then_some(needed)
}

/// Frames needed for `bytes` (ceil to the 4 KiB frame), or `None` when
/// that exceeds the driver's PRDT budget.
pub fn frames_for(bytes: usize) -> Option<usize> {
    if bytes == 0 {
        return None;
    }
    let frames = bytes.div_ceil(crate::FRAME_BYTES);
    (frames <= DATA_FRAMES).then_some(frames)
}

/// Number of PRDT entries that describe `total` bytes split every
/// `frame` bytes — the "a 128 KiB transfer over 4 KiB frames is 32
/// descriptors" arithmetic, independent of how the driver allocates.
///
/// `None` for zero/oversized input or a frame size outside the PRDT's
/// representable range.
pub fn prdt_count(total: usize, frame: usize) -> Option<u16> {
    if total == 0 || frame == 0 || frame > PRDT_MAX_ENTRY_BYTES || total > MAX_PRDT_BYTES {
        return None;
    }
    let count = total.div_ceil(frame);
    u16::try_from(count).ok()
}

/// `(offset, len)` of PRDT segment `index` for a `total`-byte transfer
/// split every `frame` bytes; the last segment carries the partial tail.
/// `None` past the end.
pub fn prdt_segment(total: usize, frame: usize, index: usize) -> Option<(usize, usize)> {
    let count = usize::from(prdt_count(total, frame)?);
    if index >= count {
        return None;
    }
    let offset = index.checked_mul(frame)?;
    let len = (total - offset).min(frame);
    Some((offset, len))
}

/// Largest PRDT entry (`cmd::PRDT_MAX_BYTES`), re-exported so the
/// geometry checks and the entry builder cannot drift.
const PRDT_MAX_ENTRY_BYTES: usize = crate::cmd::PRDT_MAX_BYTES;
/// Sum of all PRDT entries is bounded by the 16-bit count.
const MAX_PRDT_BYTES: usize = PRDT_MAX_ENTRY_BYTES * crate::cmd::MAX_PRDT_ENTRIES;

/// Little-endian word `n` of a byte buffer (`None` when the buffer is
/// too short — every IDENTIFY read is validated before use).
fn word(id: &[u8], n: usize) -> Option<u16> {
    let at = n.checked_mul(2)?;
    let bytes = id.get(at..at + 2)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

/// Total addressable sector count from an IDENTIFY DEVICE parameter
/// block, preferring the 48-bit value when the device advertises it.
///
/// `None` when the block is shorter than 512 bytes or reports zero
/// capacity — the caller then treats the drive as unusable, exactly as
/// `ata::identify` does.
pub fn identify_sectors(id: &[u8]) -> Option<u64> {
    if id.len() < 512 {
        return None;
    }
    let lba48 = word(id, 83)? & (1 << 10) != 0;
    let sectors = if lba48 {
        let (lo, hi) = (word(id, 100)?, word(id, 101)?);
        let (hi2, hi3) = (word(id, 102)?, word(id, 103)?);
        u64::from(lo) | (u64::from(hi) << 16) | (u64::from(hi2) << 32) | (u64::from(hi3) << 48)
    } else {
        let (lo, hi) = (word(id, 60)?, word(id, 61)?);
        u64::from(lo) | (u64::from(hi) << 16)
    };
    (sectors != 0).then_some(sectors)
}

/// Decode the 40-byte model string (IDENTIFY words 27..46) into `out`,
/// in the order a human reads it: ATA stores each word "byte swapped",
/// so the first character is the word's high byte (ATA8-ACS2 §7.16;
/// the same decode `ata::identify` performs word by word).
///
/// Returns `false` (and leaves `out` untouched) for a block shorter
/// than 512 bytes.
pub fn identify_model(id: &[u8], out: &mut [u8; 40]) -> bool {
    if id.len() < 512 {
        return false;
    }
    for (i, pair) in out.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let Some(w) = word(id, 27 + i) else {
            return false;
        };
        pair[0] = (w >> 8) as u8;
        pair[1] = w as u8;
    }
    true
}
