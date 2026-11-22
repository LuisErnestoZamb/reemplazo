//! Adversarial host tests for `ahci-wire`: every layout, decode and
//! builder is exercised with valid, boundary and hostile inputs. The
//! crate is pure (`no_std`, `forbid(unsafe_code)`), so these tests run
//! the same code the kernel runs — only the MMIO glue differs.

use ahci_wire::cmd;
use ahci_wire::fis::{self, H2dFis};
use ahci_wire::geometry;
use ahci_wire::reg;
use ahci_wire::status::{self, PortError, TaskFile};

// ---------------------------------------------------------------------------
// Register map: the offsets the kernel writes through
// ---------------------------------------------------------------------------

#[test]
fn hba_registers_match_ahci_1_3_1_table_3() {
    assert_eq!(reg::HBA_CAP, 0x00);
    assert_eq!(reg::HBA_GHC, 0x04);
    assert_eq!(reg::HBA_IS, 0x08);
    assert_eq!(reg::HBA_PI, 0x0C);
    assert_eq!(reg::HBA_VS, 0x10);
    assert_eq!(reg::HBA_BOHC, 0x28);
}

#[test]
fn port_windows_are_0x80_apart_from_0x100() {
    assert_eq!(reg::port_reg(0, reg::PORT_CMD), Some(0x100 + 0x18));
    assert_eq!(reg::port_reg(1, reg::PORT_CMD), Some(0x180 + 0x18));
    assert_eq!(
        reg::port_reg(31, reg::PORT_CI),
        Some(0x100 + 31 * 0x80 + 0x38)
    );
    // Hardware data: an out-of-range port index is refused, never wrapped.
    assert_eq!(reg::port_reg(32, reg::PORT_CMD), None);
    assert_eq!(reg::port_reg(255, 0), None);
}

#[test]
fn cap_decode_counts_slots_and_ports() {
    // QEMU's CAP: (ports-1) | (31 << 8) | ... → 32 slots.
    let qemu_cap = 5u32 | (31 << 8) | (1 << 20) | (1 << 30) | (1 << 18) | (1 << 31);
    assert_eq!(reg::command_slots(qemu_cap), 32);
    assert!(qemu_cap & reg::CAP_S64A != 0);
    // One slot / one port: the minimum legal HBA.
    let minimal = 0u32;
    assert_eq!(reg::command_slots(minimal), 1);
    assert_eq!(reg::command_slots(0x0000_0300), 4);
    // PI is a 32-bit port bitmap.
    assert!(reg::port_implemented(0b1010, 1));
    assert!(!reg::port_implemented(0b1010, 2));
    assert!(!reg::port_implemented(0xFFFF_FFFF, 32));
}

#[test]
fn command_bits_match_the_spec_and_qemu() {
    assert_eq!(reg::CMD_ST, 1 << 0);
    assert_eq!(reg::CMD_SUD, 1 << 1);
    assert_eq!(reg::CMD_POD, 1 << 2);
    assert_eq!(reg::CMD_FRE, 1 << 4);
    assert_eq!(reg::CMD_FR, 1 << 14);
    assert_eq!(reg::CMD_CR, 1 << 15);
    // The read-only mask must contain both running bits and the CCS field
    // (QEMU PORT_CMD_RO_MASK is the same set).
    assert_eq!(reg::CMD_READ_ONLY_MASK, 0x007D_FFE0);
    assert_ne!(reg::CMD_READ_ONLY_MASK & reg::CMD_CR, 0);
    assert_ne!(reg::CMD_READ_ONLY_MASK & reg::CMD_FR, 0);
}

#[test]
fn signature_and_phy_values() {
    assert_eq!(reg::SIG_ATA, 0x0000_0101);
    assert_eq!(reg::SIG_ATAPI, 0xEB14_0101);
    assert!(reg::device_present(0x0000_0103));
    assert!(!reg::device_present(0x0000_0000)); // no device
    assert!(!reg::device_present(0x0000_0101)); // device but PHY not up
}

// ---------------------------------------------------------------------------
// PxIS / PxTFD decoding
// ---------------------------------------------------------------------------

#[test]
fn port_error_bits_are_the_spec_numbers() {
    assert_eq!(status::IS_DHRS, 1);
    assert_eq!(status::IS_TFES, 1 << 30);
    assert_eq!(status::IS_HBFS, 1 << 29);
    assert_eq!(status::IS_HBDS, 1 << 28);
    assert_eq!(status::IS_IFS, 1 << 27);
    assert_eq!(status::IS_INFS, 1 << 26);
    assert_eq!(status::IS_OFS, 1 << 24);
    assert_eq!(status::IS_IPMS, 1 << 23);
    // Normal-completion FISes are not errors.
    assert_eq!(status::IS_ERROR & status::IS_DHRS, 0);
    assert_eq!(status::IS_ERROR & status::IS_PSS, 0);
    assert_eq!(status::IS_ERROR & status::IS_SDBS, 0);
}

#[test]
fn first_error_prefers_task_file_and_reports_none_when_clean() {
    assert_eq!(status::first_error(0), None);
    assert_eq!(status::first_error(status::IS_DHRS | status::IS_PSS), None);
    assert_eq!(
        status::first_error(status::IS_TFES | status::IS_HBFS),
        Some(PortError::TaskFile)
    );
    assert_eq!(
        status::first_error(status::IS_HBFS),
        Some(PortError::HostBusFatal)
    );
    assert_eq!(
        status::first_error(status::IS_OFS),
        Some(PortError::Overflow)
    );
    assert_eq!(
        status::first_error(status::IS_IPMS),
        Some(PortError::IncorrectPortMultiplier)
    );
    // Every error name is non-empty (the serial log depends on it).
    for err in [
        PortError::TaskFile,
        PortError::HostBusFatal,
        PortError::HostBusData,
        PortError::InterfaceFatal,
        PortError::InterfaceNonFatal,
        PortError::Overflow,
        PortError::IncorrectPortMultiplier,
    ] {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn task_file_decodes_status_and_error_halves() {
    let idle = TaskFile::from_tfd(0x0000_0050); // DRDY, no ERR/BSY/DRQ
    assert!(!idle.err() && !idle.bsy() && !idle.drq() && idle.idle_ok());
    assert_eq!(idle.error, 0);

    let failed = TaskFile::from_tfd(0x0000_0401); // ERR status + ABRT error
    assert!(failed.err() && !failed.bsy() && !failed.idle_ok());
    assert_eq!(failed.error, status::ATA_ERR_ABRT);
    assert_eq!(status::taskfile_error_name(failed.error), "command aborted");

    let busy = TaskFile::from_tfd(0x0000_0080);
    assert!(busy.bsy() && !busy.idle_ok());

    assert_eq!(
        status::taskfile_error_name(status::ATA_ERR_IDNF),
        "ID not found"
    );
    assert_eq!(status::taskfile_error_name(0), "unknown error");
}

// ---------------------------------------------------------------------------
// Register Host to Device FIS
// ---------------------------------------------------------------------------

#[test]
fn identify_fis_has_the_spec_shape() {
    let f = H2dFis::identify();
    let b = f.bytes();
    assert_eq!(b[0], fis::TYPE_H2D);
    assert_eq!(b[1], fis::FIS_C); // C=1, PMP=0
    assert_eq!(b[2], fis::CMD_IDENTIFY_DEVICE);
    assert_eq!(b[3], 0); // feature low
    assert_eq!(b[7], fis::DEVICE_LBA);
    assert_eq!(b[11], 0); // feature high
    assert_eq!(f.command(), 0xEC);
    assert_eq!(f.cfl(), 5); // 20 bytes / 4
}

#[test]
fn lba48_read_fis_carries_all_48_address_bits() {
    // 0x00_1234_5678_9ABC — each byte distinct so a swapped/truncated
    // field fails the test.
    let lba = 0x0000_1234_5678_9ABC_u64;
    let f = H2dFis::read_dma_ext(lba, 7).expect("valid request");
    let b = f.bytes();
    assert_eq!(b[0], 0x27);
    assert_eq!(b[1], 0x80);
    assert_eq!(b[2], 0x25);
    assert_eq!(b[3], 0); // feature low (must be 0 for DMA EXT)
    assert_eq!(b[4], 0xBC);
    assert_eq!(b[5], 0x9A);
    assert_eq!(b[6], 0x78);
    assert_eq!(b[7], 0x40); // LBA mode, DEV 0
    assert_eq!(b[8], 0x56);
    assert_eq!(b[9], 0x34);
    assert_eq!(b[10], 0x12);
    assert_eq!(b[11], 0);
    assert_eq!(b[12], 7);
    assert_eq!(b[13], 0);
    assert_eq!(b[14], 0);
    assert_eq!(b[15], 0);
    assert_eq!(f.lba(), lba);
    assert_eq!(f.count(), 7);
}

#[test]
fn write_dma_fis_differs_only_in_the_command_byte() {
    let r = H2dFis::read_dma_ext(4096, 128).expect("read");
    let w = H2dFis::write_dma_ext(4096, 128).expect("write");
    assert_eq!(w.command(), 0x35);
    for (i, (&a, &b)) in r.bytes().iter().zip(w.bytes()).enumerate() {
        if i == 2 {
            assert_ne!(a, b);
        } else {
            assert_eq!(a, b, "byte {i} differs between read and write");
        }
    }
}

#[test]
fn fis_refuses_zero_count_and_out_of_window_lbas() {
    assert!(H2dFis::read_dma_ext(0, 0).is_none());
    assert!(H2dFis::write_dma_ext(0, 0).is_none());
    assert!(H2dFis::read_dma_ext(1 << 48, 1).is_none());
    assert!(H2dFis::read_dma_ext(u64::MAX, 1).is_none());
    // The top of the window is legal: 2^48 - 1.
    let top = H2dFis::read_dma_ext((1 << 48) - 1, 1).expect("top LBA");
    assert_eq!(top.lba(), (1 << 48) - 1);
    // 16-bit count is legal as-is; a count of 65535 is not 0.
    let wide = H2dFis::read_dma_ext(0, 65535).expect("wide count");
    assert_eq!(wide.count(), 65535);
}

#[test]
fn fis_count_splits_across_low_and_high_bytes() {
    let f = H2dFis::read_dma_ext(0, 0x1234).expect("count");
    assert_eq!(f.bytes()[12], 0x34);
    assert_eq!(f.bytes()[13], 0x12);
}

// ---------------------------------------------------------------------------
// Command header + PRDT entries
// ---------------------------------------------------------------------------

#[test]
fn header_dword0_composes_cfl_write_and_prdtl() {
    let table = 0x0000_0000_0001_2380u64; // 128-byte aligned
    let d = cmd::header_dwords(cmd::CFL_H2D, false, 16, table).expect("read header");
    assert_eq!(d[0], 5 | (16 << 16));
    assert_eq!(d[1], 0);
    assert_eq!(u64::from(d[2]) | (u64::from(d[3]) << 32), table);

    let w = cmd::header_dwords(cmd::CFL_H2D, true, 32, table).expect("write header");
    assert_eq!(w[0], 5 | cmd::HDR_WRITE | (32 << 16));
    assert_ne!(w[0] & cmd::HDR_WRITE, 0);
}

#[test]
fn header_refuses_illegal_cfl_and_misaligned_table() {
    let ok = 0x1_0000u64;
    assert!(cmd::header_dwords(1, false, 1, ok).is_none()); // below 2
    assert!(cmd::header_dwords(17, false, 1, ok).is_none()); // above 16
    assert!(cmd::header_dwords(2, false, 1, ok + 4).is_none()); // unaligned
    assert!(cmd::header_dwords(16, false, 1, ok).is_some()); // boundary
}

#[test]
fn prdt_entry_encodes_byte_count_minus_one_and_high_dword() {
    let d = cmd::prdt_dwords(0x0000_0000_0010_0000, 4096, true).expect("entry");
    assert_eq!(d[0], 0x0010_0000);
    assert_eq!(d[1], 0);
    assert_eq!(d[2], 0);
    assert_eq!(d[3] & !cmd::PRDT_INTERRUPT, 4096 - 1);
    assert_ne!(d[3] & cmd::PRDT_INTERRUPT, 0);

    // Above 4 GiB: the high dword must carry the address (64-bit DMA).
    let high = cmd::prdt_dwords(0x0000_0001_0000_2000, 512, false).expect("entry");
    assert_eq!(high[0], 0x0000_2000);
    assert_eq!(high[1], 1);
    assert_eq!(high[3], 511);
}

#[test]
fn prdt_entry_refuses_empty_oversized_and_odd_addresses() {
    assert!(cmd::prdt_dwords(0, 0, false).is_none());
    assert!(cmd::prdt_dwords(0, cmd::PRDT_MAX_BYTES + 1, false).is_none());
    assert!(cmd::prdt_dwords(0, cmd::PRDT_MAX_BYTES, false).is_some());
    // DBA[1:0] must be zero (AHCI 1.3.1 §4.3).
    assert!(cmd::prdt_dwords(2, 512, false).is_none());
    assert!(cmd::prdt_dwords(1, 512, false).is_none());
}

#[test]
fn hardware_structs_have_the_spec_sizes() {
    assert_eq!(core::mem::size_of::<cmd::CommandHeader>(), 32);
    assert_eq!(core::mem::size_of::<cmd::PrdtEntry>(), 16);
    assert_eq!(cmd::LIST_BYTES, 1024);
    assert_eq!(cmd::TABLE_PRDT, 0x80);
    assert_eq!(cmd::FIS_BYTES, 256);
}

// ---------------------------------------------------------------------------
// Transfer geometry
// ---------------------------------------------------------------------------

#[test]
fn sector_counts_are_whole_and_bounded() {
    assert_eq!(geometry::sectors_for(0), None);
    assert_eq!(geometry::sectors_for(511), None);
    assert_eq!(geometry::sectors_for(513), None);
    assert_eq!(geometry::sectors_for(512), Some(1));
    assert_eq!(geometry::sectors_for(128 * 1024), Some(256));
    assert_eq!(geometry::sectors_for(128 * 1024 + 512), None);
    assert_eq!(geometry::sectors_for(256 * 1024), None);
}

#[test]
fn a_256_sector_request_splits_into_two_128_sector_commands() {
    let mut plan = [(0u64, 0u16); 4];
    let n = geometry::split_request(1_000_000, 256, &mut plan).expect("split");
    assert_eq!(n, 2);
    assert_eq!(&plan[..n], &[(1_000_000, 128), (1_000_128, 128)]);

    // 129 sectors → 128 + 1; 1 sector → one command.
    let n = geometry::split_request(0, 129, &mut plan).expect("split");
    assert_eq!(&plan[..n], &[(0, 128), (128, 1)]);
    let n = geometry::split_request(0, 1, &mut plan).expect("split");
    assert_eq!(&plan[..n], &[(0, 1)]);

    assert_eq!(geometry::next_chunk(0), None);
    assert_eq!(geometry::next_chunk(1), Some(1));
    assert_eq!(geometry::next_chunk(256), Some(128));
}

#[test]
fn split_request_refuses_zero_oversize_and_a_short_output() {
    let mut plan = [(0u64, 0u16); 1];
    assert_eq!(geometry::split_request(0, 0, &mut plan), None);
    assert_eq!(geometry::split_request(0, 257, &mut plan), None);
    assert_eq!(geometry::split_request(0, 256, &mut plan), None); // two needed
    let mut one = [(0u64, 0u16); 1];
    assert_eq!(geometry::split_request(0, 128, &mut one), Some(1));
}

#[test]
fn a_128_kib_transfer_is_32_prdt_entries_over_4_kib_frames() {
    assert_eq!(geometry::prdt_count(128 * 1024, 4096), Some(32));
    assert_eq!(geometry::prdt_count(128 * 1024, 8192), Some(16));
    let last = geometry::prdt_segment(128 * 1024, 4096, 31).expect("last segment");
    assert_eq!(last, (31 * 4096, 4096));
    assert_eq!(geometry::prdt_segment(128 * 1024, 4096, 32), None);
}

#[test]
fn prdt_segments_carry_a_partial_tail() {
    // 130 KiB: 32 full 4 KiB entries plus a 2 KiB tail.
    let total = 130 * 1024;
    assert_eq!(geometry::prdt_count(total, 4096), Some(33));
    assert_eq!(
        geometry::prdt_segment(total, 4096, 32),
        Some((131_072, 2048))
    );
    // Non-multiple sizes: 3000 bytes is one 3000-byte entry.
    assert_eq!(geometry::prdt_count(3000, 4096), Some(1));
    assert_eq!(geometry::prdt_segment(3000, 4096, 0), Some((0, 3000)));
    // The segments tile the transfer exactly, no gaps or overlaps.
    let mut next = 0;
    for i in 0..33 {
        let (off, len) = geometry::prdt_segment(total, 4096, i).unwrap();
        assert_eq!(off, next);
        next += len;
    }
    assert_eq!(next, total);
    assert_eq!(geometry::prdt_count(0, 4096), None);
    assert_eq!(geometry::prdt_count(4096, 0), None);
}

#[test]
fn dma_frame_budget_matches_the_command_cap() {
    assert_eq!(geometry::DATA_FRAMES, 16);
    assert_eq!(geometry::frames_for(geometry::MAX_CMD_BYTES), Some(16));
    assert_eq!(geometry::frames_for(1), Some(1));
    assert_eq!(geometry::frames_for(4097), Some(2));
    assert_eq!(geometry::frames_for(geometry::MAX_CMD_BYTES + 1), None);
    assert_eq!(geometry::frames_for(0), None);
}

// ---------------------------------------------------------------------------
// IDENTIFY DEVICE decoding
// ---------------------------------------------------------------------------

/// Fill `id` words from a list of (word index, value) pairs.
fn identify_block(words: &[(usize, u16)]) -> std::vec::Vec<u8> {
    let mut id = std::vec![0u8; 512];
    for &(n, v) in words {
        id[n * 2..n * 2 + 2].copy_from_slice(&v.to_le_bytes());
    }
    id
}

#[test]
fn identify_prefers_the_lba48_capacity() {
    let id = identify_block(&[
        (83, 1 << 10),
        (60, 0x1111),
        (61, 0x2222),
        (100, 0x0010),
        (101, 0x0000),
        (102, 0x0000),
        (103, 0x0000),
    ]);
    assert_eq!(geometry::identify_sectors(&id), Some(0x0010));
}

#[test]
fn identify_falls_back_to_lba28_and_refuses_zero_capacity() {
    let id = identify_block(&[(60, 0x1234), (61, 0x0001)]);
    assert_eq!(geometry::identify_sectors(&id), Some(0x0001_1234));
    let empty = identify_block(&[(60, 0), (61, 0)]);
    assert_eq!(geometry::identify_sectors(&empty), None);
    // Short buffer (a lying transfer length) is refused, never read past.
    assert_eq!(geometry::identify_sectors(&[0u8; 511]), None);
}

#[test]
fn identify_model_byte_swaps_each_word() {
    // "AB" is stored as word 0x4241? No: ATA stores 'A' in the *high*
    // byte, so the word value is 0x4142 for "AB".
    let mut words = std::vec![(27usize, u16::from_be_bytes(*b"AB"))];
    words.push((28, u16::from_be_bytes(*b" C")));
    let id = identify_block(&words);
    let mut out = [0u8; 40];
    assert!(geometry::identify_model(&id, &mut out));
    assert_eq!(&out[..3], b"AB ");
    assert_eq!(out[3], b'C');
    assert!(!geometry::identify_model(&[0u8; 510], &mut out));
}
