//! Fail-closed ELF64 (little-endian, x86-64) parser for the userland module.
//!
//! This file is deliberately **core-only**: it contains no kernel glue, no
//! allocator use and no `crate::` references, so the exact same source is
//! host-tested adversarially through `xtask/tests/elf_hostile.rs` (which
//! includes it via `#[path]`). The kernel side lives in `load.rs`; the module
//! capture in `module.rs`.
//!
//! Contract (hito 1): `ET_EXEC`, `e_phentsize == 56`, at most 16 program
//! headers, `PT_LOAD` segments with `p_vaddr` in `[USER_BASE, USER_END)`,
//! `p_filesz <= p_memsz`, no `PF_W | PF_X`, and a `p_align` that is a
//! power of two >= 4 KiB with `p_vaddr ≡ p_offset (mod p_align)`.
//! Everything is read through `get()`/`checked_*`; no `unwrap`, no direct
//! indexing of the input and no arithmetic that can overflow.

#![forbid(unsafe_code)]

/// First virtual address reserved for user processes (PML4[1], 512 GiB).
/// Kept in sync with `memory::USER_BASE`, which owns the page-table side.
pub const USER_BASE: u64 = 0x0000_0080_0000_0000;
/// One PDPT entry above [`USER_BASE`] (1 GiB of user address space).
pub const USER_END: u64 = USER_BASE + (1 << 30);

/// 4 KiB mapping granularity (the target's baseline page size).
pub const PAGE_SIZE: u64 = 4096;
/// Hard cap on program headers we will even look at.
pub const MAX_PHNUM: usize = 16;

const EHDR_SIZE: u64 = 64;
const PHDR_SIZE: u64 = 56;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const EV_CURRENT: u32 = 1;
const PT_LOAD: u32 = 1;
/// ELF `PF_W` — the loader maps such pages writable (still user, never exec
/// enforced until EFER.NXE is enabled by the privilege milestone).
pub const PF_W: u32 = 2;
const PF_X: u32 = 1;

/// Why a module was refused. Printed via `{:?}` by the kernel's `FATAL: elf:`
/// line; a malformed module never silently becomes a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    BadClass,
    BadData,
    BadIdentVersion,
    BadType,
    BadMachine,
    BadVersion,
    BadEhsize,
    BadPhentsize,
    NoProgramHeaders,
    TooManyProgramHeaders,
    BadPhoff,
    TruncatedProgramHeaders,
    BadSegmentFlags { index: usize },
    EmptySegment { index: usize },
    SegmentTooLarge { index: usize },
    SegmentOutsideFile { index: usize },
    SegmentOutsideUser { index: usize },
    BadAlignment { index: usize },
    OverlappingSegments { first: usize, second: usize },
    NoLoadSegments,
    EntryOutsideUser,
    EntryNotInLoad,
}

/// One validated `PT_LOAD` range. `offset` is the byte range in the module,
/// `vaddr` the range in the process; only `filesz` bytes come from the file,
/// the rest of `memsz` must be zero-filled by the loader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub flags: u32,
}

/// Validated image: the entry point plus at most [`MAX_PHNUM`] load segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfImage<'a> {
    pub entry: u64,
    raw: &'a [u8],
    segments: [Segment; MAX_PHNUM],
    count: usize,
}

impl<'a> ElfImage<'a> {
    /// The validated load segments, in program-header order.
    pub fn segments(&self) -> &[Segment] {
        // `count` is only ever advanced after writing `segments[count]`.
        &self.segments[..self.count]
    }

    /// Module bytes, for the loader's file → page copies.
    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }
}

/// Little-endian scalar reads; every one is bounds-checked against `buf`.
/// A field outside the buffer is reported as `BadPhoff` (the only error
/// variant for "declared offset cannot be read"), never as a panic.
fn u16_at(buf: &[u8], off: u64) -> Result<u16, ElfError> {
    let start = usize::try_from(off).map_err(|_| ElfError::BadPhoff)?;
    let bytes: [u8; 2] = buf
        .get(start..start.checked_add(2).ok_or(ElfError::BadPhoff)?)
        .and_then(|s| s.try_into().ok())
        .ok_or(ElfError::BadPhoff)?;
    Ok(u16::from_le_bytes(bytes))
}

fn u32_at(buf: &[u8], off: u64) -> Result<u32, ElfError> {
    let start = usize::try_from(off).map_err(|_| ElfError::BadPhoff)?;
    let bytes: [u8; 4] = buf
        .get(start..start.checked_add(4).ok_or(ElfError::BadPhoff)?)
        .and_then(|s| s.try_into().ok())
        .ok_or(ElfError::BadPhoff)?;
    Ok(u32::from_le_bytes(bytes))
}

fn u64_at(buf: &[u8], off: u64) -> Result<u64, ElfError> {
    let start = usize::try_from(off).map_err(|_| ElfError::BadPhoff)?;
    let bytes: [u8; 8] = buf
        .get(start..start.checked_add(8).ok_or(ElfError::BadPhoff)?)
        .and_then(|s| s.try_into().ok())
        .ok_or(ElfError::BadPhoff)?;
    Ok(u64::from_le_bytes(bytes))
}

fn subslice(buf: &[u8], off: u64, len: u64) -> Option<&[u8]> {
    let start = usize::try_from(off).ok()?;
    let len = usize::try_from(len).ok()?;
    buf.get(start..start.checked_add(len)?)
}

/// Validate the ELF header and every `PT_LOAD` program header. Returns
/// `Err` for *any* deviation — there is no partial-acceptance path.
pub fn parse(raw: &[u8]) -> Result<ElfImage<'_>, ElfError> {
    if (raw.len() as u64) < EHDR_SIZE {
        return Err(ElfError::TooShort);
    }
    if raw.get(0..4) != Some(&[0x7f, b'E', b'L', b'F'][..]) {
        return Err(ElfError::BadMagic);
    }
    if raw.get(4) != Some(&2) {
        return Err(ElfError::BadClass);
    }
    if raw.get(5) != Some(&1) {
        return Err(ElfError::BadData);
    }
    if raw.get(6) != Some(&1) {
        return Err(ElfError::BadIdentVersion);
    }
    if u16_at(raw, 16)? != ET_EXEC {
        return Err(ElfError::BadType);
    }
    if u16_at(raw, 18)? != EM_X86_64 {
        return Err(ElfError::BadMachine);
    }
    if u32_at(raw, 20)? != EV_CURRENT {
        return Err(ElfError::BadVersion);
    }
    if u16_at(raw, 52)? as u64 != EHDR_SIZE {
        return Err(ElfError::BadEhsize);
    }
    if u16_at(raw, 54)? as u64 != PHDR_SIZE {
        return Err(ElfError::BadPhentsize);
    }
    let phnum = u16_at(raw, 56)? as usize;
    if phnum == 0 {
        return Err(ElfError::NoProgramHeaders);
    }
    if phnum > MAX_PHNUM {
        return Err(ElfError::TooManyProgramHeaders);
    }
    let phoff = u64_at(raw, 32)?;

    let mut segments = [Segment {
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        flags: 0,
    }; MAX_PHNUM];
    let mut count = 0usize;

    for i in 0..phnum {
        let ph_off = u64::try_from(i)
            .ok()
            .and_then(|i| i.checked_mul(PHDR_SIZE))
            .and_then(|delta| phoff.checked_add(delta))
            .ok_or(ElfError::BadPhoff)?;
        let ph = subslice(raw, ph_off, PHDR_SIZE).ok_or(ElfError::TruncatedProgramHeaders)?;
        if u32_at(ph, 0)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(ph, 4)?;
        let offset = u64_at(ph, 8)?;
        let vaddr = u64_at(ph, 16)?;
        let filesz = u64_at(ph, 32)?;
        let memsz = u64_at(ph, 40)?;
        let align = u64_at(ph, 48)?;

        if flags & PF_W != 0 && flags & PF_X != 0 {
            return Err(ElfError::BadSegmentFlags { index: i });
        }
        if memsz == 0 {
            return Err(ElfError::EmptySegment { index: i });
        }
        if filesz > memsz {
            return Err(ElfError::SegmentTooLarge { index: i });
        }
        let file_end = offset
            .checked_add(filesz)
            .ok_or(ElfError::SegmentOutsideFile { index: i })?;
        if file_end > raw.len() as u64 {
            return Err(ElfError::SegmentOutsideFile { index: i });
        }
        let seg_end = vaddr
            .checked_add(memsz)
            .ok_or(ElfError::SegmentOutsideUser { index: i })?;
        if vaddr < USER_BASE || seg_end > USER_END {
            return Err(ElfError::SegmentOutsideUser { index: i });
        }
        if align > 1
            && (!align.is_power_of_two() || align < PAGE_SIZE || vaddr % align != offset % align)
        {
            return Err(ElfError::BadAlignment { index: i });
        }
        // Overlapping load ranges would let a later segment overwrite an
        // earlier one's code/rodata; refuse instead of guessing.
        for prior in segments.iter().take(count) {
            let prior_end = prior.vaddr.saturating_add(prior.memsz);
            if vaddr < prior_end && prior.vaddr < seg_end {
                return Err(ElfError::OverlappingSegments {
                    first: prior.vaddr as usize,
                    second: vaddr as usize,
                });
            }
        }
        if count >= MAX_PHNUM {
            return Err(ElfError::TooManyProgramHeaders);
        }
        segments[count] = Segment {
            offset,
            vaddr,
            filesz,
            memsz,
            flags,
        };
        count += 1;
    }
    if count == 0 {
        return Err(ElfError::NoLoadSegments);
    }
    let entry = u64_at(raw, 24)?;
    if !(USER_BASE..USER_END).contains(&entry) {
        return Err(ElfError::EntryOutsideUser);
    }
    if !segments
        .iter()
        .take(count)
        .any(|s| entry >= s.vaddr && entry < s.vaddr.saturating_add(s.filesz))
    {
        return Err(ElfError::EntryNotInLoad);
    }
    Ok(ElfImage {
        entry,
        raw,
        segments,
        count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal ELF with one `PT_LOAD`, tweaked by the caller.
    #[derive(Clone)]
    struct Builder {
        raw: Vec<u8>,
        phoff: u64,
    }

    fn put_u16(buf: &mut [u8], off: usize, value: u16) {
        let bytes = value.to_le_bytes();
        buf[off..off + 2].copy_from_slice(&bytes);
    }

    fn put_u32(buf: &mut [u8], off: usize, value: u32) {
        let bytes = value.to_le_bytes();
        buf[off..off + 4].copy_from_slice(&bytes);
    }

    fn put_u64(buf: &mut [u8], off: usize, value: u64) {
        let bytes = value.to_le_bytes();
        buf[off..off + 8].copy_from_slice(&bytes);
    }

    impl Builder {
        /// `payload` is placed at file offset 0x1000 and mapped at
        /// `USER_BASE + 0x1000` (a canonical ET_EXEC layout).
        fn new(payload: &[u8]) -> Self {
            let mut raw = vec![0u8; 0x1000 + payload.len()];
            raw[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
            raw[4] = 2; // ELFCLASS64
            raw[5] = 1; // ELFDATA2LSB
            raw[6] = 1; // EV_CURRENT
            put_u16(&mut raw, 16, ET_EXEC);
            put_u16(&mut raw, 18, EM_X86_64);
            put_u32(&mut raw, 20, EV_CURRENT);
            put_u64(&mut raw, 24, USER_BASE + 0x1000);
            put_u64(&mut raw, 32, 64); // e_phoff
            put_u16(&mut raw, 52, 64); // e_ehsize
            put_u16(&mut raw, 54, 56); // e_phentsize
            put_u16(&mut raw, 56, 1); // e_phnum
            raw[0x1000..].copy_from_slice(payload);
            let mut this = Self { raw, phoff: 64 };
            this.write_phdr(
                0,
                PT_LOAD,
                5,
                0x1000,
                USER_BASE + 0x1000,
                payload.len() as u64,
                payload.len() as u64,
                0x1000,
            );
            this
        }

        // Deliberately mirrors the 7 fields of an ELF64 program header;
        // grouping them in a struct would only obscure the test setup.
        #[allow(clippy::too_many_arguments)]
        fn write_phdr(
            &mut self,
            index: usize,
            kind: u32,
            flags: u32,
            offset: u64,
            vaddr: u64,
            filesz: u64,
            memsz: u64,
            align: u64,
        ) {
            let start = (self.phoff as usize) + index * 56;
            put_u32(&mut self.raw, start, kind);
            put_u32(&mut self.raw, start + 4, flags);
            put_u64(&mut self.raw, start + 8, offset);
            put_u64(&mut self.raw, start + 16, vaddr);
            put_u64(&mut self.raw, start + 32, filesz);
            put_u64(&mut self.raw, start + 40, memsz);
            put_u64(&mut self.raw, start + 48, align);
        }

        fn bytes(&self) -> &[u8] {
            &self.raw
        }
    }

    #[test]
    fn accepts_a_canonical_executable() {
        let b = Builder::new(b"hello");
        let img = parse(b.bytes()).expect("canonical ET_EXEC must parse");
        assert_eq!(img.entry, USER_BASE + 0x1000);
        assert_eq!(img.segments().len(), 1);
        let s = img.segments()[0];
        assert_eq!(s.offset, 0x1000);
        assert_eq!(s.vaddr, USER_BASE + 0x1000);
        assert_eq!(s.filesz, 5);
        assert_eq!(s.memsz, 5);
        assert_eq!(s.flags, 5);
        assert_eq!(img.bytes(), b.bytes());
    }

    #[test]
    fn skips_non_load_headers() {
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, 4 /* PT_NOTE */, 4, 0, 0, 0, 0, 0);
        b.write_phdr(1, PT_LOAD, 5, 0x1000, USER_BASE + 0x1000, 5, 5, 0x1000);
        put_u16(&mut b.raw, 56, 2);
        let img = parse(b.bytes()).expect("PT_NOTE must be ignored");
        assert_eq!(img.segments().len(), 1);
        assert_eq!(img.segments()[0].vaddr, USER_BASE + 0x1000);
    }

    #[test]
    fn refuses_truncated_and_short_headers() {
        assert_eq!(parse(&[]), Err(ElfError::TooShort));
        assert_eq!(parse(&[0x7f, b'E', b'L', b'F']), Err(ElfError::TooShort));
        let mut b = Builder::new(b"hello");
        b.raw.truncate(70); // phdr at 64 needs 56 bytes
        assert_eq!(parse(&b.raw), Err(ElfError::TruncatedProgramHeaders));
    }

    #[test]
    fn refuses_bad_ident_and_fields() {
        let mut b = Builder::new(b"hello");
        b.raw[1] = b'X';
        assert_eq!(parse(b.bytes()), Err(ElfError::BadMagic));
        let mut b = Builder::new(b"hello");
        b.raw[4] = 1;
        assert_eq!(parse(b.bytes()), Err(ElfError::BadClass));
        let mut b = Builder::new(b"hello");
        b.raw[5] = 2;
        assert_eq!(parse(b.bytes()), Err(ElfError::BadData));
        let mut b = Builder::new(b"hello");
        b.raw[6] = 2;
        assert_eq!(parse(b.bytes()), Err(ElfError::BadIdentVersion));
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 16, 3); // ET_DYN needs relocations we do not do
        assert_eq!(parse(b.bytes()), Err(ElfError::BadType));
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 18, 3); // EM_386
        assert_eq!(parse(b.bytes()), Err(ElfError::BadMachine));
        let mut b = Builder::new(b"hello");
        put_u32(&mut b.raw, 20, 2);
        assert_eq!(parse(b.bytes()), Err(ElfError::BadVersion));
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 52, 63);
        assert_eq!(parse(b.bytes()), Err(ElfError::BadEhsize));
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 54, 32);
        assert_eq!(parse(b.bytes()), Err(ElfError::BadPhentsize));
    }

    #[test]
    fn refuses_bad_program_header_table() {
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 56, 0);
        assert_eq!(parse(b.bytes()), Err(ElfError::NoProgramHeaders));
        let mut b = Builder::new(b"hello");
        put_u16(&mut b.raw, 56, MAX_PHNUM as u16 + 1);
        assert_eq!(parse(b.bytes()), Err(ElfError::TooManyProgramHeaders));
        let mut b = Builder::new(b"hello");
        put_u64(&mut b.raw, 32, u64::MAX - 8);
        assert_eq!(parse(b.bytes()), Err(ElfError::TruncatedProgramHeaders));
        let mut b = Builder::new(b"hello");
        let len = b.raw.len() as u64;
        put_u64(&mut b.raw, 32, len);
        assert_eq!(parse(b.bytes()), Err(ElfError::TruncatedProgramHeaders));
    }

    #[test]
    fn refuses_hostile_segments() {
        let mut b = Builder::new(b"hello");
        b.write_phdr(
            0,
            PT_LOAD,
            7, /* RWX */
            0x1000,
            USER_BASE + 0x1000,
            5,
            5,
            0x1000,
        );
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::BadSegmentFlags { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1000, USER_BASE + 0x1000, 5, 0, 0x1000);
        assert_eq!(parse(b.bytes()), Err(ElfError::EmptySegment { index: 0 }));
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1000, USER_BASE + 0x1000, 6, 5, 0x1000);
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentTooLarge { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(
            0,
            PT_LOAD,
            5,
            0x1000,
            USER_BASE + 0x1000,
            5,
            u64::MAX,
            0x1000,
        );
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentOutsideUser { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(
            0,
            PT_LOAD,
            5,
            0x1000,
            USER_BASE + 0x1000,
            u64::MAX,
            u64::MAX,
            0x1000,
        );
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentOutsideFile { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(
            0,
            PT_LOAD,
            5,
            u64::MAX - 2,
            USER_BASE + 0x1000,
            5,
            5,
            0x1000,
        );
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentOutsideFile { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1000, u64::MAX - 8, 5, 5, 0x1000);
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentOutsideUser { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1000, 0x20_0000, 5, 5, 0x1000);
        assert_eq!(
            parse(b.bytes()),
            Err(ElfError::SegmentOutsideUser { index: 0 })
        );
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1001, USER_BASE + 0x1000, 4, 4, 0x1000);
        assert_eq!(parse(b.bytes()), Err(ElfError::BadAlignment { index: 0 }));
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, PT_LOAD, 5, 0x1000, USER_BASE + 0x1000, 5, 5, 3);
        assert_eq!(parse(b.bytes()), Err(ElfError::BadAlignment { index: 0 }));
    }

    #[test]
    fn refuses_no_load_and_overlapping_loads() {
        let mut b = Builder::new(b"hello");
        b.write_phdr(0, 4 /* PT_NOTE */, 4, 0, 0, 0, 0, 0);
        assert_eq!(parse(b.bytes()), Err(ElfError::NoLoadSegments));
        let payload = [0u8; 32];
        let mut b = Builder::new(&payload);
        b.write_phdr(0, PT_LOAD, 5, 0x1000, USER_BASE + 0x1000, 5, 16, 0x1000);
        b.write_phdr(1, PT_LOAD, 4, 0x1008, USER_BASE + 0x1008, 5, 5, 0x1000);
        put_u16(&mut b.raw, 56, 2);
        assert!(matches!(
            parse(b.bytes()),
            Err(ElfError::OverlappingSegments { .. })
        ));
    }

    #[test]
    fn refuses_bad_entry() {
        let mut b = Builder::new(b"hello");
        put_u64(&mut b.raw, 24, 0x1000);
        assert_eq!(parse(b.bytes()), Err(ElfError::EntryOutsideUser));
        let mut b = Builder::new(b"hello");
        put_u64(&mut b.raw, 24, USER_BASE + 0x9000);
        assert_eq!(parse(b.bytes()), Err(ElfError::EntryNotInLoad));
    }
}
