//! Safe, bounds-checked parser for the Multiboot2 **boot information**
//! structure (the one GRUB passes in EBX), per the GNU Multiboot2 spec 2.0,
//! §3.6.
//!
//! Pure byte-slice logic: `forbid(unsafe_code)` and host-testable. The
//! kernel performs the only unsafe step (raw pointer → slice) before calling
//! [`BootInfo::parse`].
//!
//! Note: boot-information tags use `u32 type, u32 size` headers (§3.6.2).
//! The *header* tags inside the OS image use `u16 type, u16 flags, u32 size`
//! (§3.1.3) — a different layout; do not mix them up.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

/// Bootloader told us this region is ordinary available RAM (§3.6.8).
pub const MMAP_AVAILABLE: u32 = 1;

/// Why a boot information buffer was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    /// Fewer than the 8-byte fixed part.
    TooSmall,
    /// `total_size` declares more bytes than the buffer actually holds.
    BadTotalSize { declared: u32, available: usize },
    /// A tag header or body would cross the `total_size` boundary.
    TruncatedTag { offset: usize },
    /// A tag declared `size < 8` (header itself would not fit).
    InvalidTagSize { offset: usize, size: u32 },
    /// No terminating `type=0, size=8` tag (§3.6.2).
    MissingEndTag,
}

/// A validated boot information buffer; all accessors are bounds-checked.
#[derive(Debug, PartialEq, Eq)]
pub struct BootInfo<'a> {
    /// Exactly `total_size` bytes, already walked and validated.
    raw: &'a [u8],
}

/// One memory-map entry (§3.6.8). `kind` == [`MMAP_AVAILABLE`] means usable RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub length: u64,
    pub kind: u32,
}

/// Framebuffer description (§3.6.12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framebuffer {
    pub addr: u64,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    /// 0 = indexed, 1 = direct RGB, 2 = EGA text (§3.6.12).
    pub kind: u8,
}

/// Iterator over memory-map entries; never panics on truncated input.
#[derive(Debug, PartialEq, Eq)]
pub struct MemoryMap<'a> {
    entries: &'a [u8],
    entry_size: usize,
}

impl MemoryRegion {
    pub fn is_available(&self) -> bool {
        self.kind == MMAP_AVAILABLE
    }
}

impl<'a> Iterator for MemoryMap<'a> {
    type Item = MemoryRegion;

    fn next(&mut self) -> Option<MemoryRegion> {
        // entry_size >= 24 enforced by the constructor; re-check defensively.
        if self.entry_size < 24 || self.entries.len() < self.entry_size {
            return None;
        }
        let entry = self.entries.get(..self.entry_size)?;
        let region = MemoryRegion {
            base: read_u64(entry, 0)?,
            length: read_u64(entry, 8)?,
            kind: read_u32(entry, 16)?,
        };
        self.entries = self.entries.get(self.entry_size..).unwrap_or(&[]);
        Some(region)
    }
}

impl<'a> BootInfo<'a> {
    /// Parse and validate a raw buffer. `raw` may be longer than
    /// `total_size`; only the declared prefix is retained.
    pub fn parse(raw: &'a [u8]) -> Result<Self, ParseError> {
        let declared = read_u32(raw, 0).ok_or(ParseError::TooSmall)?;
        let total = declared as usize;
        if total < 8 {
            return Err(ParseError::TooSmall);
        }
        if total > raw.len() {
            return Err(ParseError::BadTotalSize {
                declared,
                available: raw.len(),
            });
        }
        let raw = &raw[..total];

        // Walk tags: each starts 8-byte aligned (§3.6.2), ends with type 0.
        let mut offset = 8usize;
        while offset + 8 <= total {
            let ty = read_u32(raw, offset).ok_or(ParseError::TruncatedTag { offset })?;
            let size = read_u32(raw, offset + 4).ok_or(ParseError::TruncatedTag { offset })?;
            if size < 8 {
                return Err(ParseError::InvalidTagSize { offset, size });
            }
            let end: usize = (offset as u64 + size as u64)
                .try_into()
                .map_err(|_| ParseError::TruncatedTag { offset })?;
            if end > total {
                return Err(ParseError::TruncatedTag { offset });
            }
            if ty == 0 {
                // Terminating tag: spec requires type 0, size 8.
                if size != 8 {
                    return Err(ParseError::InvalidTagSize { offset, size });
                }
                return Ok(Self { raw });
            }
            // Advance to the next 8-byte-aligned offset (size may need padding).
            offset = end
                .checked_add(7)
                .ok_or(ParseError::TruncatedTag { offset })?
                & !7;
        }
        Err(ParseError::MissingEndTag)
    }

    /// Declared `total_size` of the structure.
    pub fn total_size(&self) -> usize {
        self.raw.len()
    }

    /// First tag of `ty`, returning its body (bytes after the 8-byte header).
    fn tag_body(&self, ty: u32) -> Option<&'a [u8]> {
        let total = self.raw.len();
        let mut offset = 8usize;
        while offset + 8 <= total {
            let this_ty = read_u32(self.raw, offset)?;
            let size = read_u32(self.raw, offset + 4)? as usize;
            if size < 8 || offset + size > total {
                return None; // validated in parse(); defensive
            }
            let body = self.raw.get(offset + 8..offset + size)?;
            if this_ty == ty {
                return Some(body);
            }
            if this_ty == 0 {
                return None;
            }
            offset = (offset + size).checked_add(7)? & !7;
        }
        None
    }

    /// Boot loader name, e.g. `"GRUB 2.12"` (tag type 2, §3.6.9).
    pub fn bootloader_name(&self) -> Option<&'a str> {
        let body = self.tag_body(2)?;
        let end = body.iter().position(|&b| b == 0).unwrap_or(body.len());
        core::str::from_utf8(body.get(..end)?).ok()
    }

    /// `(mem_lower, mem_upper)` in KiB (tag type 4, §3.6.3).
    pub fn basic_memory_kb(&self) -> Option<(u32, u32)> {
        let body = self.tag_body(4)?;
        Some((read_u32(body, 0)?, read_u32(body, 4)?))
    }

    /// Memory map (tag type 6, §3.6.8), if the bootloader provided one.
    pub fn memory_map(&self) -> Option<MemoryMap<'a>> {
        let body = self.tag_body(6)?;
        let entry_size = read_u32(body, 0)? as usize;
        if entry_size < 24 {
            return None;
        }
        Some(MemoryMap {
            entries: body.get(8..)?, // skip entry_size + entry_version
            entry_size,
        })
    }

    /// Framebuffer info (tag type 8, §3.6.12), if present.
    pub fn framebuffer(&self) -> Option<Framebuffer> {
        let body = self.tag_body(8)?;
        Some(Framebuffer {
            addr: read_u64(body, 0)?,
            pitch: read_u32(body, 8)?,
            width: read_u32(body, 12)?,
            height: read_u32(body, 16)?,
            bpp: *body.get(20)?,
            kind: *body.get(21)?,
        })
    }
}

/// Bounds-checked little-endian reads; `None` instead of panicking.
fn read_u32(buf: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(buf: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = buf.get(offset..end)?.try_into().ok()?;
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// Build a well-formed buffer: 8-byte fixed part + tags + end tag.
    /// Each tag body is placed 8-aligned with `u32 type, u32 size` headers.
    fn buffer(tags: &[(u32, &[u8])]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&0u32.to_le_bytes()); // total_size, patched below
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        for &(ty, body) in tags {
            let size = 8 + body.len();
            v.extend_from_slice(&ty.to_le_bytes());
            v.extend_from_slice(&(size as u32).to_le_bytes());
            v.extend_from_slice(body);
            while v.len() % 8 != 0 {
                v.push(0);
            }
        }
        // Terminating tag: type 0, size 8.
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&8u32.to_le_bytes());
        let total = v.len() as u32;
        v[0..4].copy_from_slice(&total.to_le_bytes());
        v
    }

    #[test]
    fn minimal_structure_parses() {
        let v = buffer(&[]);
        let info = BootInfo::parse(&v).unwrap();
        assert_eq!(info.total_size(), v.len());
        assert_eq!(info.bootloader_name(), None);
        assert_eq!(info.basic_memory_kb(), None);
        assert_eq!(info.memory_map(), None);
        assert_eq!(info.framebuffer(), None);
    }

    #[test]
    fn reads_bootloader_name() {
        let v = buffer(&[(2, b"GRUB 2.12\0")]);
        let info = BootInfo::parse(&v).unwrap();
        assert_eq!(info.bootloader_name(), Some("GRUB 2.12"));
    }

    #[test]
    fn name_without_nul_and_invalid_utf8_is_none() {
        let v = buffer(&[(2, b"GRUB")]);
        assert_eq!(BootInfo::parse(&v).unwrap().bootloader_name(), Some("GRUB"));
        let v = buffer(&[(2, b"\xff\xfe")]);
        assert_eq!(BootInfo::parse(&v).unwrap().bootloader_name(), None);
    }

    #[test]
    fn reads_basic_memory() {
        let mut body = Vec::new();
        body.extend_from_slice(&640u32.to_le_bytes());
        body.extend_from_slice(&261120u32.to_le_bytes());
        let v = buffer(&[(4, &body)]);
        assert_eq!(
            BootInfo::parse(&v).unwrap().basic_memory_kb(),
            Some((640, 261120))
        );
    }

    #[test]
    fn memory_map_iterates_with_entry_size_24() {
        let mut body = Vec::new();
        body.extend_from_slice(&24u32.to_le_bytes()); // entry_size
        body.extend_from_slice(&0u32.to_le_bytes()); // entry_version
        // entry 0: available RAM
        body.extend_from_slice(&0x100000u64.to_le_bytes());
        body.extend_from_slice(&0x9f000u64.to_le_bytes());
        body.extend_from_slice(&1u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        // entry 1: reserved
        body.extend_from_slice(&0xfec00000u64.to_le_bytes());
        body.extend_from_slice(&0x1000u64.to_le_bytes());
        body.extend_from_slice(&2u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let v = buffer(&[(6, &body)]);
        let info = BootInfo::parse(&v).unwrap();
        let regions: Vec<_> = info.memory_map().unwrap().collect();
        assert_eq!(regions.len(), 2);
        assert!(regions[0].is_available());
        assert_eq!(regions[0].base, 0x100000);
        assert_eq!(regions[0].length, 0x9f000);
        assert!(!regions[1].is_available());
    }

    #[test]
    fn oversized_entry_size_yields_no_regions() {
        let mut body = Vec::new();
        body.extend_from_slice(&16u32.to_le_bytes()); // < 24 → rejected
        body.extend_from_slice(&0u32.to_le_bytes());
        let v = buffer(&[(6, &body)]);
        assert_eq!(BootInfo::parse(&v).unwrap().memory_map(), None);
    }

    #[test]
    fn reads_framebuffer() {
        let mut body = Vec::new();
        body.extend_from_slice(&0xfd000000u64.to_le_bytes());
        body.extend_from_slice(&5120u32.to_le_bytes()); // pitch
        body.extend_from_slice(&1280u32.to_le_bytes());
        body.extend_from_slice(&800u32.to_le_bytes());
        body.push(32); // bpp
        body.push(1); // direct RGB
        let v = buffer(&[(8, &body)]);
        let fb = BootInfo::parse(&v).unwrap().framebuffer().unwrap();
        assert_eq!(fb.addr, 0xfd000000);
        assert_eq!((fb.width, fb.height, fb.bpp, fb.kind), (1280, 800, 32, 1));
    }

    #[test]
    fn rejects_declared_total_larger_than_buffer() {
        let mut v = buffer(&[]);
        v[0..4].copy_from_slice(&4096u32.to_le_bytes());
        assert!(matches!(
            BootInfo::parse(&v),
            Err(ParseError::BadTotalSize { declared: 4096, .. })
        ));
    }

    #[test]
    fn rejects_tiny_or_zero_total() {
        assert!(matches!(BootInfo::parse(&[]), Err(ParseError::TooSmall)));
        let mut v = buffer(&[]);
        v[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(matches!(BootInfo::parse(&v), Err(ParseError::TooSmall)));
    }

    #[test]
    fn rejects_tag_size_smaller_than_header() {
        // Manual buffer (no end tag): fixed part + a tag declaring size=4.
        let mut v = Vec::new();
        v.extend_from_slice(&16u32.to_le_bytes()); // total_size = fixed + tag hdr
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&2u32.to_le_bytes()); // type = 2
        v.extend_from_slice(&4u32.to_le_bytes()); // size = 4 (< 8) → invalid
        assert_eq!(
            BootInfo::parse(&v),
            Err(ParseError::InvalidTagSize { offset: 8, size: 4 })
        );
    }

    #[test]
    fn rejects_tag_crossing_total_boundary() {
        // Tag header fits inside total_size, but body (size=64) does not.
        let mut v = Vec::new();
        v.extend_from_slice(&24u32.to_le_bytes()); // total_size = 24
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&2u32.to_le_bytes()); // type
        v.extend_from_slice(&64u32.to_le_bytes()); // size
        v.extend_from_slice(&[0u8; 8]); // pad to declared total
        assert_eq!(
            BootInfo::parse(&v),
            Err(ParseError::TruncatedTag { offset: 8 })
        );
    }

    #[test]
    fn rejects_missing_end_tag() {
        // Well-formed tag but total_size ends before any terminating tag.
        let mut v = Vec::new();
        v.extend_from_slice(&24u32.to_le_bytes()); // total_size
        v.extend_from_slice(&0u32.to_le_bytes()); // reserved
        v.extend_from_slice(&4u32.to_le_bytes()); // type 4 (basic meminfo)
        v.extend_from_slice(&16u32.to_le_bytes()); // size 16, but only 8 bytes left
        v.extend_from_slice(&[0u8; 8]); // pad to declared total, no end tag
        assert_eq!(BootInfo::parse(&v), Err(ParseError::MissingEndTag));
    }

    #[test]
    fn pads_to_8_byte_alignment_between_tags() {
        // tag with 1-byte body → next tag must start 8-aligned (header 9 bytes → pad to 16).
        let v = buffer(&[(2, b"X\0"), (4, &[1, 0, 0, 0, 2, 0, 0, 0])]);
        let info = BootInfo::parse(&v).unwrap();
        assert_eq!(info.bootloader_name(), Some("X"));
        assert_eq!(info.basic_memory_kb(), Some((1, 2)));
    }
}
