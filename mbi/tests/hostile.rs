//! Adversarial inputs for the `multiboot2` parser the kernel hands its
//! boot information to — the ported suite of the removed `bootinfo`
//! crate (docs/small-swaps-eval.md §4), adapted to this crate's *pointer*
//! API.
//!
//! Every buffer here is 8-aligned and owns **≥ the declared
//! `total_size` bytes**: `load` has no buffer length, so a test declaring
//! more than it owns would read out of bounds itself. The case that
//! therefore has no pointer-API equivalent — "declared `total_size` larger
//! than the real buffer" (`bootinfo`'s `rejects_declared_total_larger_than_buffer`)
//! — is exactly the contract `mbi::check_range` (kernel-side, bounded by
//! `MBI_MAX_BYTES`) enforces; it is documented on `read_mbi` and unit
//! tested there.

use multiboot2::{
    BootInformation, BootInformationHeader, FramebufferType, LoadError, MemoryAreaType,
};

/// 8-aligned, `N`-byte buffer for the pointer API.
#[repr(C, align(8))]
struct Aligned<const N: usize>([u8; N]);

impl<const N: usize> Aligned<N> {
    /// Leaked, zero-padded copy of `bytes` — `'static` so the parsed
    /// `BootInformation` cannot outlive its buffer inside a test (host
    /// tests only: `std` is available for `Box`).
    fn leak(bytes: &[u8]) -> &'static mut Self {
        assert!(bytes.len() <= N);
        let mut buf = [0u8; N];
        buf[..bytes.len()].copy_from_slice(bytes);
        Box::leak(Box::new(Self(buf)))
    }
}

/// `BootInformation::load` over a test-owned buffer.
fn load(bytes: &[u8]) -> Result<BootInformation<'static>, LoadError> {
    // SAFETY: the test owns ≥ the declared `total_size` bytes, the buffer
    // is 8-aligned (`Aligned`), and nothing mutates it concurrently — the
    // exact caller contract `mbi::check_range` enforces in `read_mbi`.
    unsafe { BootInformation::load(bytes.as_ptr().cast::<BootInformationHeader>()) }
}

/// 8-aligned, leaked, zero-padded copy of `bytes` in an `N`-byte buffer.
fn blob<const N: usize>(bytes: &[u8; N]) -> &'static mut [u8; N] {
    &mut Aligned::<N>::leak(bytes).0
}

/// Well-formed 48-byte MBI: header + basic memory info (type 4) +
/// bootloader name (type 2, "GRUB") + end tag.
const GOOD: [u8; 48] = [
    // header: total_size = 48, reserved = 0
    0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // tag type=4 (basic memory info), size=16
    0x04, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
    // mem_lower=640, mem_upper=261120 (0x3FC00)
    0x80, 0x02, 0x00, 0x00, 0x00, 0xFC, 0x03, 0x00,
    // tag type=2 (bootloader name), size=13, body "GRUB\0", pad to 8
    0x02, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x00, 0x00, b'G', b'R', b'U', b'B', 0x00, 0x00, 0x00, 0x00,
    // end tag: type=0, size=8
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
];

/// 80-byte MBI with a memory map (type 6): two 24-byte areas — available
/// RAM at 1 MiB and a reserved region — the data `memory::init` feeds the
/// frame allocator from.
const MMAP: [u8; 80] = [
    // header: total_size = 80, reserved = 0
    0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tag type=6 (mmap), size=64
    0x06, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // entry_size = 24, entry_version = 0
    0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // area 0: base 0x100000, len 0x9f000, type 1 (available), reserved
    0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // area 1: base 0xfec00000, len 0x1000, type 2 (reserved)
    0x00, 0x00, 0xC0, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // end tag: type=0, size=8
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
];

/// 56-byte MBI with a direct-RGB framebuffer (type 8, §3.6.12).
const FB: [u8; 56] = [
    // header: total_size = 56, reserved = 0
    0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // tag type=8 (framebuffer), size=38 (32-byte base + 6 RGB field bytes)
    0x08, 0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, // address = 0xfd000000
    0x00, 0x00, 0x00, 0xFD, 0x00, 0x00, 0x00, 0x00,
    // pitch = 5120, width = 1280, height = 800
    0x00, 0x14, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x20, 0x03, 0x00, 0x00,
    // bpp = 32, type = 1 (direct RGB), padding u16 = 0
    0x20, 0x01, 0x00, 0x00, // RGB field: red pos/size, green pos/size, blue pos/size
    16, 8, 8, 8, 0, 8, // pad to the 8-byte tag boundary (tag ends at 46)
    0x00, 0x00, // end tag: type=0, size=8
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
];

#[test]
fn well_formed_blob_loads_and_maps_accessors() {
    let info = load(blob(&GOOD)).unwrap();
    assert_eq!(info.total_size(), 48);
    let name = info.boot_loader_name_tag().expect("name tag");
    assert_eq!(name.name().unwrap(), "GRUB");
    let basic = info.basic_memory_info_tag().expect("meminfo tag");
    assert_eq!((basic.memory_lower(), basic.memory_upper()), (640, 261120));
    // tags we don't provide → None (our old Option accessors)
    assert!(info.memory_map_tag().is_none());
    assert!(info.framebuffer_tag().is_none());
}

#[test]
fn memory_map_accessors_match_the_old_iterator() {
    let info = load(blob(&MMAP)).unwrap();
    let areas = info.memory_map_tag().expect("mmap tag").memory_areas();
    assert_eq!(areas.len(), 2);
    // was: region.is_available() / region.base / region.length
    assert_eq!(areas[0].typ(), MemoryAreaType::Available);
    assert_eq!(areas[0].start_address(), 0x10_0000);
    assert_eq!(areas[0].size(), 0x9_f000);
    assert_eq!(areas[1].typ(), MemoryAreaType::Reserved);
}

#[test]
fn framebuffer_accessors_match_the_old_struct() {
    let info = load(blob(&FB)).unwrap();
    let fb = info
        .framebuffer_tag()
        .expect("framebuffer tag")
        .expect("known framebuffer type");
    assert_eq!(fb.address(), 0xfd00_0000);
    assert_eq!(
        (fb.pitch(), fb.width(), fb.height(), fb.bpp()),
        (5120, 1280, 800, 32)
    );
    // kind as the old raw byte carried it: 1 = direct RGB (§3.6.12)
    assert!(matches!(fb.buffer_type(), Ok(FramebufferType::RGB { .. })));
}

#[test]
fn null_and_misaligned_pointers_rejected() {
    assert!(matches!(
        unsafe { BootInformation::load(core::ptr::null()) },
        Err(LoadError::Memory(_))
    ));
    let unaligned = &blob(&GOOD)[1..]; // base + 1: never 8-aligned
    assert!(matches!(
        unsafe { BootInformation::load(unaligned.as_ptr().cast()) },
        Err(LoadError::Memory(_))
    ));
}

#[test]
fn tiny_or_unaligned_total_size_rejected() {
    let bytes = blob(&[0u8; 64]);
    bytes[..GOOD.len()].copy_from_slice(&GOOD);
    // 0 and 4: the 8-byte header itself would not fit; 49: not 8-aligned
    // and the tag walk cannot end exactly at it. All reads stay inside
    // the owned 64 bytes.
    for total in [0u32, 4, 49] {
        bytes[0..4].copy_from_slice(&total.to_le_bytes());
        assert!(load(&*bytes).is_err(), "total_size={total} accepted");
    }
}

#[test]
fn tag_size_below_header_rejected() {
    let bytes = blob(&GOOD);
    bytes[12] = 4; // first tag declares size = 4 (< the 8-byte header)
    assert!(load(&*bytes).is_err());
}

#[test]
fn tag_crossing_declared_boundary_rejected() {
    let bytes = blob(&GOOD);
    bytes[12] = 0x40; // tag header fits, body (size 64) crosses total_size
    assert!(load(&*bytes).is_err());
}

#[test]
fn missing_end_tag_rejected() {
    let bytes = blob(&GOOD);
    // structure ends exactly where the end tag would start
    bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
    assert!(matches!(load(&*bytes), Err(LoadError::NoEndTag)));
}

#[test]
fn end_tag_with_wrong_size_rejected() {
    let bytes = blob(&GOOD);
    bytes[44] = 16; // terminating tag must be type 0, size 8 (§3.6.2)
    assert!(load(&*bytes).is_err());
}

#[test]
fn declared_total_past_the_walk_end_rejected() {
    // Closest pointer-API analogue of bootinfo's
    // `rejects_declared_total_larger_than_buffer`: declare more bytes than
    // the tag walk actually fills, with the buffer ≥ the declaration so
    // the read itself stays in bounds. The untestable twin — declared >
    // *buffer* — is `mbi::check_range`'s contract, not the crate's.
    let bytes = blob(&[0u8; 8192]);
    bytes[..GOOD.len()].copy_from_slice(&GOOD);
    bytes[0..4].copy_from_slice(&4096u32.to_le_bytes());
    assert!(load(&*bytes).is_err());
}
