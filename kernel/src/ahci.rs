//! AHCI (SATA) disk driver — the MacBook2,1's ICH7 disk path.
//!
//! The 2007 MacBook's ICH7 south bridge runs its SATA ports in **AHCI**
//! mode, where the legacy IDE ports 0x1F0/0x3F6 that `crate::ata`
//! polls are not the path at all. This module drives the controller the
//! way the milestone asks: PCI class 01h/06h/01h → BAR5 (ABAR) MMIO →
//! per-port bring-up (PxSIG / spin-up / PxCMD ST|FRE handshake) →
//! `IDENTIFY DEVICE` + LBA48 `READ/WRITE DMA EXT` through a command
//! list, a received-FIS area, one command table and a PRDT that
//! scatter/gathers 4 KiB frames.
//!
//! Register offsets, bit positions, FIS fields, the command header and
//! PRDT layouts, transfer geometry and the IDENTIFY decode all live in
//! the `ahci-wire` crate (host-tested, `forbid(unsafe_code)`); this
//! module is only the MMIO/DMA glue — the project's `unsafe` budget.
//! Sources are cited there per field (AHCI 1.3.1, SATA 3.2, ATA8-ACS2,
//! QEMU 10.0.13 `hw/ide/ahci.c`); nothing here is remembered.
//!
//! ## DMA and cache coherency (x86-64, no IOMMU)
//!
//! The boot path is identity-mapped (`entry.S` maps the first 4 GiB
//! with the default WB memory type), so a physical address returned by
//! `memory::alloc()` is also a valid kernel virtual address: the command
//! list, received-FIS area, command table and data frames go to the HBA
//! as *physical* addresses and the CPU touches the same bytes. There is
//! no IOMMU and no non-coherent memory type: on x86, PCI bus-master DMA
//! snoops the CPU caches, so no explicit cache flush/invalidate is
//! needed; what *is* needed is ordering — descriptor/FIS/PRDT writes
//! must reach memory before the PxCI doorbell, hence `fence(SeqCst)`
//! exactly like `crate::e1000` before TDT. The reverse argument makes
//! the device's writes visible once PxCI clears.
//!
//! ## Bounded, fail-closed
//!
//! Every wait — engine stop/start (CR/FR), COMRESET (DET), command
//! completion (PxCI) — is a bounded spin ([`POLL_LIMIT`]); a missing or
//! wedged device becomes `None`/`false`, never a hung boot. No
//! `unwrap`/`expect` touches device data; capacity is checked against
//! the IDENTIFY-reported sector count before any command is programmed.
//!
//! ## Neutrality
//!
//! [`probe`] prints nothing when no AHCI controller exists or no marked
//! disk answers — the main smoke (no AHCI device) and a diskless boot
//! stay byte-identical. `AHCI_OK` is appended to the installer smoke
//! chain only when an AHCI-attached copy of the source FAT16 volume is
//! present; the filesystem/GPT/install proofs keep running on the IDE
//! disk, and the AHCI disk is used as the *source* only when the legacy
//! channel found nothing (the MacBook's real situation).
//!
//! ## Not yet
//!
//! IRQ-driven completion (we poll PxCI; IRQ10/11 stay masked as on
//! every other device here), NCQ (`READ/WRITE FPDMA QUEUED` — one
//! command in flight today), port multipliers, hot-plug,
//! `SET FEATURES`, `FLUSH CACHE` (write-cache ordering is
//! `fat::write`'s documented future work, same as the IDE driver), and
//! real-hardware validation: QEMU's `ich9-ahci` is the test bed, the
//! MacBook's ICH7 has to confirm the same sequence on silicon.

use crate::memory::{self, Frame};
use crate::pci::{Scan, read32, write32};
use ahci_wire::cmd;
use ahci_wire::fis::H2dFis;
use ahci_wire::geometry::{self, DATA_FRAMES};
use ahci_wire::reg::{self, CMD_CR, CMD_FR};
use ahci_wire::status::{self, TaskFile};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};
use pci::{CMD_BUS_MASTER, CMD_MEMORY_SPACE, mem_bar_address};

/// Frames a disk's DMA set owns: command list (1 KiB), received FIS
/// (256 B), command table (128 B + 16 PRDT entries) and [`DATA_FRAMES`]
/// 4 KiB data frames. Each is a separate frame, so the PRDT (not
/// contiguity) is what makes a transfer one scatter/gather command.
const DMA_FRAMES: usize = 3 + DATA_FRAMES;

/// Frame size assumed by the allocator and the wire geometry; a
/// mismatch would make every PRDT segment wrong, so it is a build-time
/// error, not a comment.
const _: () = assert!(memory::FRAME_SIZE as usize == ahci_wire::FRAME_BYTES);

/// Bounded poll budget (spins), mirroring `e1000`'s `TX_POLLS`: QEMU
/// answers in microseconds, real silicon in milliseconds, and the bound
/// turns a wedged controller into a failed probe instead of a hung
/// boot. A missing device never spends it.
const POLL_LIMIT: u32 = 20_000_000;

/// `IDENTIFY DEVICE` transfers one 512-byte parameter block.
const IDENTIFY_BYTES: usize = 512;

// --- MMIO (typed 32-bit accesses to the identity-mapped ABAR) -----------

fn hba_read(mmio: u64, reg: u32) -> u32 {
    // SAFETY: `mmio` is the PCI memory BAR (ABAR), checked in
    // `controller()` to be non-zero and < 4 GiB, so it lies inside
    // `entry.S`'s identity map; `reg` is a 4-byte-aligned HBA register
    // offset; the access is a volatile device read.
    unsafe { read_volatile((mmio + u64::from(reg)) as *const u32) }
}

fn hba_write(mmio: u64, reg: u32, value: u32) {
    // SAFETY: same contract as `hba_read`; volatile device write.
    unsafe { write_volatile((mmio + u64::from(reg)) as *mut u32, value) }
}

fn port_read(mmio: u64, port: u8, reg: u32) -> Option<u32> {
    let off = reg::port_reg(port, reg)?;
    Some(hba_read(mmio, off))
}

fn port_write(mmio: u64, port: u8, reg: u32, value: u32) -> bool {
    match reg::port_reg(port, reg) {
        Some(off) => {
            hba_write(mmio, off, value);
            true
        }
        None => false,
    }
}

/// The DMA memory set one disk owns. Raw pointers into identity-mapped
/// frames; `frames` keeps the allocator handles so the frames go back to
/// the pool when a probe discards the set (`Drop`).
struct Dma {
    clb: *mut u8,
    fis: *mut u8,
    table: *mut u8,
    data: [*mut u8; DATA_FRAMES],
    frames: [Option<Frame>; DMA_FRAMES],
}

impl Dma {
    /// Allocate and zero the whole set. `None` (after returning any
    /// frames already taken) when the pool is exhausted — the caller
    /// fails the probe, never halts.
    fn alloc() -> Option<Dma> {
        let mut frames: [Option<Frame>; DMA_FRAMES] = [None; DMA_FRAMES];
        for slot in frames.iter_mut() {
            let Some(frame) = memory::alloc() else {
                // Roll back: everything allocated by this call is ours.
                for frame in frames.into_iter().flatten() {
                    memory::free(frame);
                }
                return None;
            };
            *slot = Some(frame);
        }
        let phys = |i: usize| frames[i].map(|f| f.start_phys());
        let (Some(clb), Some(fis), Some(table)) = (phys(0), phys(1), phys(2)) else {
            for frame in frames.into_iter().flatten() {
                memory::free(frame);
            }
            return None;
        };
        let mut data = [core::ptr::null_mut(); DATA_FRAMES];
        for (i, slot) in data.iter_mut().enumerate() {
            match phys(i + 3) {
                Some(p) => *slot = p as *mut u8,
                None => {
                    for frame in frames.into_iter().flatten() {
                        memory::free(frame);
                    }
                    return None;
                }
            }
        }
        let dma = Dma {
            clb: clb as *mut u8,
            fis: fis as *mut u8,
            table: table as *mut u8,
            data,
            frames,
        };
        // SAFETY: every pointer above is a freshly allocated, exclusively
        // owned 4 KiB identity-mapped frame; zeroing it before the HBA
        // ever sees it (engines are stopped until `bring_up`) is allowed
        // (no aliasing) and required (the command list/slots and PRDT
        // must start zeroed).
        unsafe {
            core::ptr::write_bytes(dma.clb, 0, memory::FRAME_SIZE as usize);
            core::ptr::write_bytes(dma.fis, 0, memory::FRAME_SIZE as usize);
            core::ptr::write_bytes(dma.table, 0, memory::FRAME_SIZE as usize);
            for frame in dma.data {
                core::ptr::write_bytes(frame, 0, memory::FRAME_SIZE as usize);
            }
        }
        Some(dma)
    }

    /// The command table is 128-byte aligned: a frame base satisfies it
    /// (AHCI 1.3.1 §4.2.2), but check instead of assuming.
    fn table_aligned(&self) -> bool {
        (self.table as u64).is_multiple_of(cmd::TABLE_ALIGN as u64)
    }
}

impl Drop for Dma {
    fn drop(&mut self) {
        for frame in self.frames.into_iter().flatten() {
            memory::free(frame);
        }
    }
}

/// One probed SATA disk on one AHCI port.
///
/// The struct owns the DMA frames shared with the device; access goes
/// through volatile reads/writes or explicit copies (never Rust
/// references to hardware-owned memory). Boot code is single-threaded.
pub(crate) struct AhciDisk {
    mmio: u64,
    port: u8,
    /// Capacity in 512-byte sectors from IDENTIFY (the same bound the
    /// IDE driver exposes, so `crate::fs`/`crate::install` treat both
    /// alike).
    sectors: u32,
    /// Model name, IDENTIFY words 27..46 decoded (untrusted bytes;
    /// sanitized on output like `ata::Drive::model_name`).
    model: [u8; 40],
    dma: Dma,
}

impl Drop for AhciDisk {
    fn drop(&mut self) {
        // The HBA may still reference the DMA frames: stop the port's
        // engines first (bounded), then `Dma`'s drop returns the frames.
        let _ = self.stop_engines();
    }
}

impl AhciDisk {
    /// The AHCI port this disk answered on (`probe_target` skips it).
    pub(crate) fn port(&self) -> u8 {
        self.port
    }

    /// Total addressable sectors from IDENTIFY.
    pub(crate) fn sectors(&self) -> u32 {
        self.sectors
    }

    /// Sanitized model string, exactly the idiom of
    /// `ata::Drive::model_name`: trailing spaces trimmed, every byte
    /// outside printable ASCII replaced with `?` — the bytes come from
    /// the device, so they never reach the console raw.
    pub(crate) fn model_name<'a>(&self, out: &'a mut [u8; 40]) -> &'a str {
        let end = self
            .model
            .iter()
            .rposition(|&b| b != b' ')
            .map_or(0, |i| i + 1);
        for (dst, &src) in out.iter_mut().take(end).zip(&self.model[..end]) {
            *dst = if src.is_ascii_graphic() || src == b' ' {
                src
            } else {
                b'?'
            };
        }
        core::str::from_utf8(&out[..end]).unwrap_or("?")
    }

    /// Read `buf.len() / 512` sectors (1..=256) starting at `lba` into
    /// `buf`, which must hold a whole number of sectors. `false` on any
    /// error, capacity violation or poll timeout — never blocks forever.
    ///
    /// 256 sectors (128 KiB — the IDE driver's documented cap, and what
    /// `install::write_sectors_at` asks for) become two 128-sector
    /// commands; the split is `ahci_wire::geometry::split_request`, so
    /// it is host-tested arithmetic rather than a loop condition
    /// reasoned about here.
    pub(crate) fn read_sectors(&self, lba: u32, buf: &mut [u8]) -> bool {
        let Some((plan, chunks)) = self.plan(lba, buf.len()) else {
            return false;
        };
        let mut off = 0usize;
        for &(chunk_lba, chunk_sectors) in &plan[..chunks] {
            let bytes = usize::from(chunk_sectors) * geometry::SECTOR_BYTES;
            let Some(part) = buf.get_mut(off..off + bytes) else {
                return false;
            };
            if !self.one_command(chunk_lba, chunk_sectors, Chunk::Read(part)) {
                return false;
            }
            off += bytes;
        }
        off == buf.len()
    }

    /// Write `buf.len() / 512` sectors (1..=256) from `buf` starting at
    /// `lba`; same contract as the read path (write-through: `true`
    /// means the device consumed the bytes).
    pub(crate) fn write_sectors(&self, lba: u32, buf: &[u8]) -> bool {
        let Some((plan, chunks)) = self.plan(lba, buf.len()) else {
            return false;
        };
        let mut off = 0usize;
        for &(chunk_lba, chunk_sectors) in &plan[..chunks] {
            let bytes = usize::from(chunk_sectors) * geometry::SECTOR_BYTES;
            let Some(part) = buf.get(off..off + bytes) else {
                return false;
            };
            if !self.one_command(chunk_lba, chunk_sectors, Chunk::Write(part)) {
                return false;
            }
            off += bytes;
        }
        off == buf.len()
    }

    /// Validate a request and split it into per-command chunks: whole
    /// sectors only, inside this disk's IDENTIFY-reported capacity, at
    /// most [`geometry::MAX_TRANSFER_SECTORS`] — the same contract the
    /// IDE driver documents, so `crate::fs`/`crate::install` cannot tell
    /// the two apart.
    fn plan(&self, lba: u32, len: usize) -> Option<([(u64, u16); 2], usize)> {
        let sectors = geometry::sectors_for(len)?;
        // Capacity bound: end of the request inside the reported count
        // (u64 arithmetic; `lba` is the shared u32 block address).
        if u64::from(lba) + u64::from(sectors) > u64::from(self.sectors) {
            return None;
        }
        let mut plan = [(0u64, 0u16); 2];
        let chunks = geometry::split_request(u64::from(lba), sectors, &mut plan)?;
        Some((plan, chunks))
    }

    /// One `READ/WRITE DMA EXT` command for at most
    /// [`geometry::MAX_CMD_SECTORS`] sectors, using the DMA frames as
    /// the PRDT's scatter/gather list.
    fn one_command(&self, lba: u64, sectors: u16, data: Chunk<'_>) -> bool {
        // The command's direction *is* the chunk's direction: deriving it
        // here makes an inconsistent (direction, buffer) pair
        // unrepresentable instead of a runtime check.
        let write = matches!(&data, Chunk::Write(_));
        let bytes = data.len();
        let Some(frame_count) = geometry::frames_for(bytes) else {
            return false;
        };
        if let Chunk::Write(buf) = &data {
            // SAFETY: for each frame we copy at most 4 KiB from `buf`,
            // whose length is `bytes` ≥ the bytes copied into that frame
            // (the last frame gets only the remainder). The frames are
            // our exclusive, identity-mapped DMA memory.
            unsafe {
                for (i, frame) in self.dma.data[..frame_count].iter().enumerate() {
                    let off = i * ahci_wire::FRAME_BYTES;
                    let len = (bytes - off).min(ahci_wire::FRAME_BYTES);
                    core::ptr::copy_nonoverlapping(buf.as_ptr().add(off), *frame, len);
                }
            }
        }

        let prdtl = match u16::try_from(frame_count) {
            Ok(n) => n,
            Err(_) => return false,
        };
        let fis = if write {
            H2dFis::write_dma_ext(lba, sectors)
        } else {
            H2dFis::read_dma_ext(lba, sectors)
        };
        let Some(fis) = fis else {
            return false;
        };
        if !self.program(fis, prdtl, bytes, write) {
            return false;
        }
        if let Chunk::Read(buf) = data {
            // SAFETY: the HBA wrote exactly `bytes` across the PRDT
            // entries after PxCI cleared (checked in `program`), and
            // `buf` is `bytes` long, so each per-frame copy stays inside
            // both `buf` and its frame.
            unsafe {
                for (i, frame) in self.dma.data[..frame_count].iter().enumerate() {
                    let off = i * ahci_wire::FRAME_BYTES;
                    let len = (bytes - off).min(ahci_wire::FRAME_BYTES);
                    core::ptr::copy_nonoverlapping(*frame, buf.as_mut_ptr().add(off), len);
                }
            }
        }
        true
    }

    /// Build slot 0 of the command list (header + CFIS + PRDT) and ring
    /// the PxCI doorbell, then wait for completion with a bound.
    fn program(&self, fis: H2dFis, prdtl: u16, bytes: usize, write: bool) -> bool {
        let table = self.dma.table as u64;
        if !self.dma.table_aligned() {
            return false;
        }
        let Some(header) = cmd::header_dwords(fis.cfl(), write, prdtl, table) else {
            return false;
        };
        // SAFETY: the command-list frame holds 32 command headers (32 B
        // each) and slot 0's four filled dwords live in its first 16
        // bytes. The table frame is exclusively ours: CFIS at 0x00 gets
        // the 20 FIS bytes, the PRDT at 0x80 one 16-byte entry per
        // frame. All writes land before the fence + PxCI below.
        unsafe {
            let head = self.dma.clb.cast::<u32>();
            for (i, dword) in header.iter().enumerate() {
                write_volatile(head.add(i), *dword);
            }
            core::ptr::copy_nonoverlapping(
                fis.bytes().as_ptr(),
                self.dma.table.add(cmd::TABLE_CFIS),
                fis.bytes().len(),
            );
            let mut off = 0usize;
            let last = usize::from(prdtl).saturating_sub(1);
            for (i, frame) in self.dma.data.iter().take(usize::from(prdtl)).enumerate() {
                let len = (bytes - off).min(ahci_wire::FRAME_BYTES);
                let Some(entry) = cmd::prdt_dwords(*frame as u64, len, i == last) else {
                    return false;
                };
                let dst = self
                    .dma
                    .table
                    .add(cmd::TABLE_PRDT + i * cmd::PRDT_ENTRY_BYTES)
                    .cast::<u32>();
                for (j, dword) in entry.iter().enumerate() {
                    write_volatile(dst.add(j), *dword);
                }
                off += len;
            }
        }
        // Command list + table + data must be in memory before the HBA
        // sees PxCI (the same ordering `e1000::transmit` uses for TDT).
        fence(Ordering::SeqCst);

        // Clear stale port status, then issue slot 0.
        if !port_write(self.mmio, self.port, reg::PORT_IS, 0xFFFF_FFFF) {
            return false;
        }
        if !port_write(self.mmio, self.port, reg::PORT_CI, 1 << 0) {
            return false;
        }

        for _ in 0..POLL_LIMIT {
            let Some(is) = port_read(self.mmio, self.port, reg::PORT_IS) else {
                return false;
            };
            if let Some(err) = status::first_error(is) {
                let tfd = port_read(self.mmio, self.port, reg::PORT_TFD).unwrap_or(0);
                let tf = TaskFile::from_tfd(tfd);
                serial_println!(
                    "ahci: port {} command failed: {} (task file: {})",
                    self.port,
                    err.as_str(),
                    status::taskfile_error_name(tf.error)
                );
                let _ = port_write(self.mmio, self.port, reg::PORT_IS, 0xFFFF_FFFF);
                return false;
            }
            let Some(ci) = port_read(self.mmio, self.port, reg::PORT_CI) else {
                return false;
            };
            if ci & 1 == 0 {
                let Some(tfd) = port_read(self.mmio, self.port, reg::PORT_TFD) else {
                    return false;
                };
                let ok = TaskFile::from_tfd(tfd).idle_ok();
                let _ = port_write(self.mmio, self.port, reg::PORT_IS, 0xFFFF_FFFF);
                return ok;
            }
            core::hint::spin_loop();
        }
        let _ = port_write(self.mmio, self.port, reg::PORT_IS, 0xFFFF_FFFF);
        false // PxCI never cleared: wedged port, fail closed
    }

    /// Stop the port's engines (AHCI 1.3.1 §10.6.1): clear ST, wait CR;
    /// clear FRE, wait FR. Bounded, best effort — used by bring-up and
    /// by `Drop`.
    fn stop_engines(&self) -> bool {
        let (mmio, port) = (self.mmio, self.port);
        let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
            return false;
        };
        if cmd & reg::CMD_ST != 0 {
            port_write(mmio, port, reg::PORT_CMD, cmd & !reg::CMD_ST);
            if !wait_cmd_bits(mmio, port, CMD_CR, false) {
                return false;
            }
        }
        let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
            return false;
        };
        if cmd & reg::CMD_FRE != 0 {
            port_write(mmio, port, reg::PORT_CMD, cmd & !reg::CMD_FRE);
            if !wait_cmd_bits(mmio, port, CMD_FR, false) {
                return false;
            }
        }
        true
    }

    /// Send `IDENTIFY DEVICE` into the first data frame and decode the
    /// capacity and model. Runs once, from `attach`, before the disk is
    /// handed out — hence `&mut self`.
    fn identify(&mut self) -> bool {
        let fis = H2dFis::identify();
        if !self.program(fis, 1, IDENTIFY_BYTES, false) {
            return false;
        }
        // SAFETY: the HBA wrote the 512-byte parameter block into the
        // first data frame (one PRDT entry of 512 bytes); reading those
        // 512 bytes back from our own frame is in bounds.
        let block = unsafe { core::slice::from_raw_parts(self.dma.data[0], IDENTIFY_BYTES) };
        if !geometry::identify_model(block, &mut self.model) {
            return false;
        }
        match geometry::identify_sectors(block) {
            Some(sectors) => {
                // The shared block contract is u32 sectors (2 TiB at
                // 512 B); a bigger disk is clamped, documented, and still
                // addressable up to that bound.
                self.sectors = u32::try_from(sectors).unwrap_or(u32::MAX);
                self.sectors != 0
            }
            None => false,
        }
    }
}

/// The slice one command moves, in the direction the caller needs.
/// `Read` is written by the device, `Write` is read from the caller —
/// keeping the two mutable/immutable borrows explicit instead of
/// casting a shared slice to a mutable pointer.
enum Chunk<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

impl Chunk<'_> {
    /// Bytes this command moves.
    fn len(&self) -> usize {
        match self {
            Chunk::Read(buf) => buf.len(),
            Chunk::Write(buf) => buf.len(),
        }
    }
}

/// Poll PxCMD until `bit` has `want` value; `false` on timeout or a
/// vanished port.
fn wait_cmd_bits(mmio: u64, port: u8, bit: u32, want: bool) -> bool {
    for _ in 0..POLL_LIMIT {
        let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
            return false;
        };
        if (cmd & bit != 0) == want {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Wait for PxSSTS.DET = 3 (device present, PHY established). False on
/// timeout — a port with nothing attached.
fn wait_device_present(mmio: u64, port: u8) -> bool {
    for _ in 0..POLL_LIMIT {
        match port_read(mmio, port, reg::PORT_SSTS) {
            Some(ssts) if reg::device_present(ssts) => return true,
            Some(_) => core::hint::spin_loop(),
            None => return false,
        }
    }
    false
}

/// Bring one port to the point where commands can be issued: COMRESET
/// if the PHY is not already up (AHCI 1.3.1 §10.5.1), program
/// PxCLB/PxFB, clear PxIS/PxSERR, spin up, then FRE → FR and ST → CR
/// (§10.6.1). Bounded at every step.
fn bring_up(mmio: u64, port: u8, dma: &Dma) -> bool {
    if !reg::device_present(port_read(mmio, port, reg::PORT_SSTS).unwrap_or(0)) {
        // PxSCTL.DET = 1 issues COMRESET; the host keeps it asserted for
        // at least 1 ms, clears it and waits for DET = 3. `pit::ticks` is
        // the only calibrated clock here and interrupts are armed before
        // the PCI scan (`main.rs`), so one tick is ≥ 10 ms > 1 ms.
        if !port_write(mmio, port, reg::PORT_SCTL, reg::SCTL_DET_COMRESET) {
            return false;
        }
        let start = crate::pit::ticks();
        while crate::pit::ticks() == start {
            core::hint::spin_loop();
        }
        if !port_write(mmio, port, reg::PORT_SCTL, 0) || !wait_device_present(mmio, port) {
            return false;
        }
    }

    // Stop both engines before reprogramming their base addresses.
    let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
        return false;
    };
    if cmd & reg::CMD_ST != 0 {
        port_write(mmio, port, reg::PORT_CMD, cmd & !reg::CMD_ST);
        if !wait_cmd_bits(mmio, port, CMD_CR, false) {
            return false;
        }
    }
    let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
        return false;
    };
    if cmd & reg::CMD_FRE != 0 {
        port_write(mmio, port, reg::PORT_CMD, cmd & !reg::CMD_FRE);
        if !wait_cmd_bits(mmio, port, CMD_FR, false) {
            return false;
        }
    }

    // Command list and received-FIS base addresses (physical == virtual:
    // identity map; see the module docs' coherency section).
    let clb = dma.clb as u64;
    let fis = dma.fis as u64;
    if !port_write(mmio, port, reg::PORT_CLB, clb as u32)
        || !port_write(mmio, port, reg::PORT_CLBU, (clb >> 32) as u32)
        || !port_write(mmio, port, reg::PORT_FB, fis as u32)
        || !port_write(mmio, port, reg::PORT_FBU, (fis >> 32) as u32)
    {
        return false;
    }
    // Write-1-to-clear the stale status latches before starting.
    port_write(mmio, port, reg::PORT_IS, 0xFFFF_FFFF);
    port_write(mmio, port, reg::PORT_SERR, 0xFFFF_FFFF);

    // Spin up (SUD) and power on (POD) the device — the documented
    // bring-up for a disk that may have been parked (§10.5.1/§10.6.1).
    // The read-modify-write writes read-only fields back with their
    // current value, which the HBA ignores by definition.
    let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
        return false;
    };
    if !port_write(mmio, port, reg::PORT_CMD, cmd | reg::CMD_SUD | reg::CMD_POD) {
        return false;
    }
    // FRE → FR, then ST → CR.
    let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
        return false;
    };
    if !port_write(mmio, port, reg::PORT_CMD, cmd | reg::CMD_FRE)
        || !wait_cmd_bits(mmio, port, CMD_FR, true)
    {
        return false;
    }
    let Some(cmd) = port_read(mmio, port, reg::PORT_CMD) else {
        return false;
    };
    if !port_write(mmio, port, reg::PORT_CMD, cmd | reg::CMD_ST)
        || !wait_cmd_bits(mmio, port, CMD_CR, true)
    {
        return false;
    }
    true
}

/// One probed AHCI controller: the ABAR already enabled, plus the
/// capability bits the probe needs.
struct Controller {
    mmio: u64,
    cap: u32,
    pi: u32,
}

/// Find the AHCI controller: PCI class 01h, sub-class 06h, prog-if 01h.
/// `None` (silent) when absent — the main smoke has no AHCI device.
fn controller(scan: &Scan) -> Option<Controller> {
    let dev = scan.devices.iter().flatten().find(|d| {
        d.class == reg::PCI_CLASS_MASS_STORAGE
            && d.subclass == reg::PCI_SUBCLASS_SATA
            && d.prog_if == reg::PCI_PROG_IF_AHCI
    })?;
    let loc = dev.location;
    // ABAR is BAR5, a 32-bit memory BAR (AHCI 1.3.1 §2.1.8; QEMU's
    // ich9-ahci registers it with `pci_register_bar(pci, 5, ...)`, and
    // Linux's libahci maps exactly AHCI_PCI_BAR = 5). Offset 0x28 is the
    // Cardbus CIS pointer on a type-0 header, not a BAR6.
    let Some(mmio) = mem_bar_address(read32(loc, reg::PCI_BAR5), 0) else {
        serial_println!("ahci: controller at {loc} has no assigned ABAR");
        return None;
    };
    if mmio >= (1u64 << 32) {
        // entry.S identity-maps 4 GiB only — an honest constraint.
        serial_println!("ahci: ABAR {mmio:#x} is outside the identity map");
        return None;
    }

    // Memory space + bus master (DMA), read-modify-write the command
    // word like `e1000::init`.
    let cmd_dword = read32(loc, 0x04);
    let want = (CMD_MEMORY_SPACE | CMD_BUS_MASTER) as u32;
    write32(
        loc,
        0x04,
        (cmd_dword & 0xFFFF_0000) | (cmd_dword as u16 | want as u16) as u32,
    );
    if read32(loc, 0x04) as u16 & want as u16 != want as u16 {
        serial_println!("ahci: could not enable memory space + bus master at {loc}");
        return None;
    }

    // GHC.AE: AHCI enable (§3.1.2). QEMU forces the bit on any GHC
    // write, so a read-back is also a first write-path proof.
    let ghc = hba_read(mmio, reg::HBA_GHC);
    hba_write(mmio, reg::HBA_GHC, ghc | reg::GHC_AE);
    if hba_read(mmio, reg::HBA_GHC) & reg::GHC_AE == 0 {
        serial_println!("ahci: GHC.AE did not stick at {loc}");
        return None;
    }

    let cap = hba_read(mmio, reg::HBA_CAP);
    let pi = hba_read(mmio, reg::HBA_PI);
    Some(Controller { mmio, cap, pi })
}

/// Probe every implemented AHCI port for an ATA disk whose LBA0 carries
/// the installer's source magic; on success print the drive line and
/// `AHCI_OK` (machine-checked by `cargo xtask smoke-install`) and hand
/// the disk to the caller.
///
/// Silent — no line at all — when no AHCI controller exists (the main
/// smoke, AGENTS.md) or no marked disk answers (a real machine's
/// unmarked disk, the disk-boot phase).
pub(crate) fn probe(scan: &Scan) -> Option<AhciDisk> {
    let ctrl = controller(scan)?;
    let mmio = ctrl.mmio;
    let pi = ctrl.pi;
    let version = hba_read(mmio, reg::HBA_VS);
    serial_println!(
        "ahci: ABAR {mmio:#010x} version {version:#06x} cap {:#010x} pi {pi:#010x} ({} slots, {} ports)",
        ctrl.cap,
        reg::command_slots(ctrl.cap),
        pi.count_ones()
    );
    let mut saw_disk = false;
    for port in 0..reg::MAX_PORTS {
        if !reg::port_implemented(pi, port) {
            continue;
        }
        let Some(dma) = Dma::alloc() else {
            serial_println!("ahci: out of frames while probing port {port}");
            return None;
        };
        let Some(disk) = attach(mmio, port, dma) else {
            continue;
        };
        saw_disk = true;
        let mut sector = [0u8; 512];
        if disk.read_sectors(0, &mut sector) && crate::ata::has_magic(&sector) {
            let mut name_buf = [0u8; 40];
            let name = disk.model_name(&mut name_buf);
            let sectors = disk.sectors();
            serial_println!(
                "ahci: port {} '{name}' {sectors} sectors ({} MiB)",
                disk.port(),
                sectors / 2048
            );
            serial_println!("AHCI_OK"); // machine-checked by `cargo xtask smoke-install`
            return Some(disk);
        }
    }
    if saw_disk {
        // A disk exists but carries no source magic: one line so a real
        // machine's log says the driver saw it; never a marker.
        serial_println!("ahci: disk found, no installer magic at LBA0");
    }
    None
}

/// Find the installer's *target* disk on the AHCI controller: an ATA
/// disk (not `source_port`) whose LBA0 carries `reemplazo-target-v1`.
/// Silent on `None`; never returns a disk it did not validate.
pub(crate) fn probe_target(scan: &Scan, source_port: Option<u8>) -> Option<AhciDisk> {
    let ctrl = controller(scan)?;
    let mmio = ctrl.mmio;
    let pi = ctrl.pi;
    for port in 0..reg::MAX_PORTS {
        if Some(port) == source_port || !reg::port_implemented(pi, port) {
            continue;
        }
        let dma = Dma::alloc()?;
        let Some(disk) = attach(mmio, port, dma) else {
            continue;
        };
        let mut sector = [0u8; 512];
        if disk.read_sectors(0, &mut sector) && crate::ata::has_target_magic(&sector) {
            return Some(disk);
        }
    }
    None
}

/// Every implemented port that answers `IDENTIFY` as an ATA disk, in
/// port order — the read-only inventory behind the shell's
/// `disks`/`install` builtins (docs/installer.md §7.1). Prints nothing
/// beyond [`controller`]'s own refusal lines (only when a controller
/// exists but cannot be used).
///
/// Re-attaching a port a boot probe already owns is deliberate and
/// safe: [`bring_up`] stops the running engines *before* it reprograms
/// `PxCLB`/`PxFB`, so the boot-time `AhciDisk` objects left in
/// `kernel_main` go stale — by the time the shell runs nothing uses
/// them any more (the shell is the kernel's idle state), and the objects
/// returned here own the port from now on. Every step is the bounded
/// probe [`probe`] already runs, so a wedged port is simply absent from
/// the listing instead of a hung shell.
pub(crate) fn list(scan: &Scan) -> alloc::vec::Vec<AhciDisk> {
    let mut found = alloc::vec::Vec::new();
    let Some(ctrl) = controller(scan) else {
        return found; // no AHCI controller (the main smoke) — empty
    };
    for port in 0..reg::MAX_PORTS {
        if !reg::port_implemented(ctrl.pi, port) {
            continue;
        }
        // A listing never *resets* a port: [`bring_up`] issues COMRESET
        // when `PxSSTS.DET` reports nothing linked and then waits its
        // whole `wait_device_present` budget for a device that is not
        // coming — measured **~18 s per empty port** in QEMU/TCG (20M
        // bounded MMIO polls), i.e. 90 s for ich9-ahci's five empty
        // ports, which is what the first `disks` run took. The boot
        // probe pays one such budget at most (it returns on the first
        // marked disk); the listing checks `DET` in one read instead.
        // A linked disk (DET = 3, what firmware leaves behind on both
        // QEMU and the MacBook) is attached exactly as `probe` does.
        if !reg::device_present(port_read(ctrl.mmio, port, reg::PORT_SSTS).unwrap_or(0)) {
            continue;
        }
        // Frame-pool exhaustion stops the listing rather than halting:
        // the disks already found are still true.
        let Some(dma) = Dma::alloc() else {
            break;
        };
        if let Some(disk) = attach(ctrl.mmio, port, dma) {
            found.push(disk);
        }
    }
    found
}

/// Bring one port up and `IDENTIFY` its disk. `None` for a port that is
/// not a ready ATA (non-ATAPI) disk — the caller silently moves on.
fn attach(mmio: u64, port: u8, dma: Dma) -> Option<AhciDisk> {
    if !bring_up(mmio, port, &dma) {
        return None;
    }
    let sig = port_read(mmio, port, reg::PORT_SIG)?;
    if sig != reg::SIG_ATA {
        // ATAPI (a CD/DVD), a port multiplier or an unknown signature:
        // not a disk this driver serves.
        return None;
    }
    let mut disk = AhciDisk {
        mmio,
        port,
        sectors: 0,
        model: [0u8; 40],
        dma,
    };
    if !disk.identify() {
        return None;
    }
    Some(disk)
}
