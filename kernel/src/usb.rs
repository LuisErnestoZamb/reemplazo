//! UHCI host controller + HID boot-keyboard driver — the MacBook's
//! real input path (docs/hardware.md §2.7 step 7; §2.1: the built-in
//! keyboard is USB HID on UHCI `00:1d.0`, and the machine has **no**
//! i8042 at all).
//!
//! # Scope and documented limits
//!
//! - **UHCI only.** EHCI/OHCI are out of scope (§2.1: the MacBook is
//!   "UHCI + EHCI only", and its keyboard is full-speed so it stays on
//!   UHCI; QEMU's smoke uses the PIIX3 companion at `00:01.2`).
//! - **Polled, no IRQ.** Interrupt-IN transfers are scheduled and
//!   polled with bounded waits, exactly like `e1000`/`ata` — IRQ-driven
//!   USB (resolving the PIRQ line) is future work (§2.7 step 8). Every
//!   wait is double-bounded: a `POLL_LIMIT` spin cap *and* a
//!   `pit::ticks()` deadline, so a dead controller fails closed in
//!   milliseconds instead of hanging boot.
//! - **Boot keyboard only.** HID *report descriptors* are declared in
//!   the config but never fetched or parsed (`usbwire` carries their
//!   length only) — the boot interface fixes the report at 8 bytes
//!   (HID 1.11 §7.1).
//! - **Decoded key events feed `keyboard.rs`'s existing set-1
//!   decoder**: this driver translates HID reports into set-1
//!   make/break bytes (`usbwire::Translator`) and hands them to the
//!   *same* `pc-keyboard` decoder the PS/2 path uses, preserving the
//!   single-consumer contract. Both wires are drained — and that can
//!   never double-type, because QEMU's input dispatch is **unicast**
//!   (`qemu_input_event_send_impl` in `ui/input.c` delivers each event
//!   to exactly one handler; `hw/input/hid.c` `hid_init` activates the
//!   USB keyboard handler to the head of the list, so with
//!   `-device usb-kbd` every `sendkey` lands on USB and PS/2 sees
//!   none — verified by trace: zero `ps2_keyboard_event` hits for
//!   injected keys). The MacBook has no i8042 at all (§2.1), so there
//!   only the USB path exists.
//!
//! # How to verify (what the smoke does *not* cover)
//!
//! - `cargo xtask smoke` proves **enumeration + configuration**
//!   (`USB_KBD_OK`, right after `PCI_OK`) and one live interrupt-IN
//!   poll (QEMU's `usb-kbd` NAKs an idle endpoint — see the
//!   `usb: interrupt-IN` line in the log). Because QEMU's `sendkey`
//!   unicast-routes to the USB keyboard when `-device usb-kbd` is
//!   attached (module header), the smoke's `KEYBOARD_OK` typing now
//!   travels **through this driver** — HID report → `usbwire`
//!   translation → the shared set-1 decoder → line discipline.
//! - Manual check beyond the smoke: `cargo xtask run` and type on the
//!   monitor (`printf 'sendkey h\\nret\\n' | nc 127.0.0.1 <port>`) —
//!   the same path, at leisure.
//! - **Real hardware**: the MacBook keyboard path is this code plus
//!   remote observation once sky2/sshd land; validate by Option/C DVD
//!   boot (AGENTS.md). Nothing here has run on the real ICH7 UHCI yet
//!   — hardware-gated.
//!
//! # Register-level sources (nothing here is remembered)
//!
//! - **UHCI Design Guide 1.1d** (Intel, March 1996; PDF mirrors:
//!   `o3one.org/hwdocs/usb/uhci11d.pdf`,
//!   `stuff.mit.edu/afs/sipb/contrib/doc/specs/protocol/usb/UHCI11D.PDF`):
//!   §2.1.1 USBCMD (RS bit0, HCRESET bit1, GRESET bit2; **MAXP bit7**
//!   "1 = 64 bytes … maximum packet size that can be used for full
//!   speed bandwidth reclamation at the end of a frame"; **CF bit6**
//!   "has no effect on the hardware … a semaphore service for
//!   software", set as the last configuration action), §5.2.1
//!   **LEGSUP** at PCI config `C0-C1h`, default `2000h`, *Read/Write
//!   Clear*, 60h/64h trap enables in bits 0-5, W1C status in 8-11+15.
//! - **Linux `drivers/usb/host/uhci-hcd.h`** (register offsets USBCMD
//!   0, USBSTS 2, USBINTR 4, FRNUM 6, USBFLBASEADD 8, USBSOF 12,
//!   PORTSC1 16 / PORTSC2 18; USBSTS/PORTSC/TD_CTRL/TD_TOKEN bit
//!   values; `USBLEGSUP 0xc0`, `USBLEGSUP_RWC 0x8f00`,
//!   `USBRES_INTEL 0xc4`).
//! - **QEMU v10.0.0** `hw/usb/uhci-regs.h` + `hcd-uhci.c` (the same
//!   bit values as `UHCI_CMD_*`/`UHCI_STS_*`/`TD_CTRL_*`/
//!   `UHCI_PORT_*`; `uhci_reset` writes port `ctrl = 0x0080` — RES1 —
//!   but then `usb_port_reset` re-runs `uhci_attach`, which restores
//!   `CCS|CSC`, so a HCRESET does **not** hide an attached device;
//!   `usb_device_reset` in `hw/usb/core.c` sets `addr = 0` and
//!   `state = USB_STATE_DEFAULT`, which is what makes the port reset
//!   below restart enumeration at address 0; frame processing reads
//!   `fl_base + (frnum & 0x3ff) << 2`; I/O BAR on **PCI BAR 4**:
//!   "Use region 4 for consistency with real hardware"; PIIX3 device
//!   `8086:7020` created by `hw/isa/piix.c` `pci_piix_realize` when
//!   `has-usb`, which `hw/i386/pc_piix.c` sets from
//!   `machine_usb(machine)` — our `-usb` flag).
//! - **OSDev "Universal Host Controller Interface"** (probe recipe:
//!   class `0C/03/00`, I/O base in BAR4, register table matching the
//!   sources above; "start the controller by setting bit 0 and bit 7"
//!   → RS + MAXP).
//! - **`docs/hardware.md` §2.1**: the real machine — four ICH7 UHCI
//!   companions `8086:27c8..27cb` (keyboard on `00:1d.0`, port 2,
//!   Apple `05ac:021a/021b`), EHCI `8086:27cc` prog-if `20` (excluded
//!   by our probe), no i8042.
//! - **HID 1.11** §7.1/§7.2.2/§7.2.4 for the 8-byte report,
//!   SET_IDLE and SET_PROTOCOL; **USB 2.0** §9.3 for SETUP packets,
//!   §9.6.1/§9.6.3 for descriptor requests, §5.6.3 for the DATA0
//!   toggle at endpoint enable.
//!
//! The task brief mentioned "GPPTE bits" for the PIIX3 legacy enable;
//! no such mnemonic exists in the UHCI Design Guide, QEMU, Linux or
//! ReactOS (searched) — the register those sources document is
//! **LEGSUP @ `C0h`** (above), which is what [`disable_legacy`] writes.
//! That deviation is recorded in the commit message.

use crate::pci::{Scan, read32, write32};
use crate::port::inw;
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{AtomicBool, Ordering, fence};
use pci::Device;
use usbwire::{BootKeyboard, Translator, find_boot_keyboard, parse_boot_report, parse_device};

// --- PCI probe -------------------------------------------------------------
// Class 0C/03/00 = serial-bus controller / USB / UHCI (OSDev UHCI wiki;
// QEMU hcd-uhci.c sets class_id = PCI_CLASS_SERIAL_USB and
// pci_conf[PCI_CLASS_PROG] = 0x00; the MacBook's UHCI companions show
// prog-if 00 in docs/hardware.md §2.1 — the EHCI's prog-if 20 excludes
// it from this probe).
const UHCI_CLASS: u8 = 0x0C;
const UHCI_SUBCLASS: u8 = 0x03;
const UHCI_PROG_IF: u8 = 0x00;

// PCI command register (offset 0x04) bits — PCI Local Bus Spec §6.2.1:
// bit 0 I/O Space Enable, bit 2 Bus Master Enable (DMA needs both).
const CMD_IO_SPACE: u16 = 1 << 0;
const CMD_BUS_MASTER: u16 = 1 << 2;

/// UHCI's I/O BAR lives in **BAR4** (config offset 0x20): the UHCI
/// Design Guide's PCI layout, QEMU's `pci_register_bar(&s->dev, 4,
/// PCI_BASE_ADDRESS_SPACE_IO, …)` ("Use region 4 for consistency with
/// real hardware"), the OSDev probe recipe, and the MacBook's
/// `0x2080-0x209f` window (docs/hardware.md §2.1) all agree.
const IO_BAR_OFFSET: u8 = 0x20;

/// USB Legacy Support register (PCI config `C0-C1h`, UHCI Design Guide
/// §5.2.1, default `2000h`, Read/Write Clear).
const USBLEGSUP: u8 = 0xC0;
/// W1C status bits 8-11+15 written as 1 (clear the 60h/64h trap
/// statuses) with every enable bit (0-5, 7) and USBPIRQDEN (13)
/// written as 0 (no SMI traps, no USB PIRQ — we are polled). `0x8F00`
/// = ReactOS `PCI_LEGSUP_CLEAR_SMI` == Linux `USBLEGSUP_RWC`, both
/// cited; the bit meanings come from UHCI Design Guide §5.2.1.
const USBLEGSUP_DISABLE: u32 = 0x8F00;
/// Intel-specific "USB resume enable" byte (Linux `USBRES_INTEL`),
/// cleared with the read-modify-write Linux's `uhci_pci_configure_hc`
/// does for vendor Intel ("Disable platform-specific non-PME#
/// wakeup").
const USBRES_INTEL: u8 = 0xC4;

// --- UHCI I/O registers (Linux uhci-hcd.h / QEMU uhci-regs.h / OSDev) -----
const USBCMD: u16 = 0x00;
const USBSTS: u16 = 0x02;
const USBINTR: u16 = 0x04; // stays 0: this milestone is polled
const FRNUM: u16 = 0x06;
const USBFLBASEADD: u16 = 0x08; // 32-bit: low half here, high half at +2
const USBSOF: u16 = 0x0C;
const PORTSC1: u16 = 0x10; // PORTSC2 = 0x12 (Linux USBPORTSC1 = 16, +2 each)

// USBCMD bits (UHCI Design Guide §2.1.1 / Linux USBCMD_*).
const USBCMD_RS: u16 = 0x0001; // Run/Stop
const USBCMD_HCRESET: u16 = 0x0002; // HC reset (self-clearing)
const USBCMD_CF: u16 = 0x0040; // Configure Flag: "no effect on the hardware"
const USBCMD_MAXP: u16 = 0x0080; // 64-byte reclamation packets (§2.1.1)

// USBSTS bits (Linux USBSTS_*; QEMU UHCI_STS_* identical values).
const USBSTS_HCH: u16 = 0x0020; // HC Halted (set while stopped)
/// Status-change bits we acknowledge (W1C): USBINT, ERROR, RD, HSE, HCPE.
/// Deliberately **excludes** HCH: QEMU implements every status bit as
/// W1C, so writing it would clear "halted" and defeat the checks below;
/// on real hardware HCH is read-only and ignores the write either way.
const USBSTS_CLEAR: u16 = 0x001F;

// PORTSC bits (Linux USBPORTSC_*; QEMU UHCI_PORT_* same values).
const PORT_CCS: u16 = 0x0001; // Current Connect Status (RO)
const PORT_CSC: u16 = 0x0002; // Connect Status Change (W1C)
const PORT_PE: u16 = 0x0004; // Port Enable
const PORT_PEC: u16 = 0x0008; // Port Enable Change (W1C)
const PORT_LSDA: u16 = 0x0100; // Low-Speed Device Attached (RO)
const PORT_PR: u16 = 0x0200; // Port Reset (QEMU UHCI_PORT_RESET = 1 << 9)

/// Root-hub ports per UHCI controller: QEMU `UHCI_PORTS 2`
/// (hcd-uhci.h), and the ICH7 routes exactly two port pairs to UHCI #1
/// (docs/hardware.md §2.1 + the ICH7 datasheet USB signal table: "USBP0
/// … USBP1 … can be routed to UHCI controller #1") — the keyboard sits
/// on port 2 (§2.1).
const UHCI_PORTS: u16 = 2;

// --- Transfer structures (Linux uhci-hcd.h; QEMU uhci_read_td) ------------
const LINK_TERM: u32 = 0x0001; // terminate (bit 0)
const LINK_QH: u32 = 0x0002; // queue-head type (bit 1)

// TD control/status bits (Linux TD_CTRL_*; QEMU uhci-regs.h identical).
const TD_ACTIVE: u32 = 1 << 23;
const TD_STALL: u32 = 1 << 22;
const TD_DBUFERR: u32 = 1 << 21;
const TD_BABBLE: u32 = 1 << 20;
const TD_NAK: u32 = 1 << 19;
const TD_CRCTIMEO: u32 = 1 << 18;
const TD_BITSTUFF: u32 = 1 << 17;
const TD_ACTLEN_MASK: u32 = 0x7FF;
/// C_ERR field (bits 28:27) = 3: let the controller retry a failed
/// transaction before reporting an error (Linux `uhci_maxerr(3)`
/// pattern).
const TD_CERR3: u32 = 3 << 27;
/// Token bit12: the transfer targets a **low-speed** device (UHCI
/// spec "Token" field). Real keyboards (the MacBook's included) are
/// low-speed HID; QEMU's usb-kbd is full-speed, which is why the
/// smoke never needed this bit before.
const TD_LOW_SPEED: u32 = 1 << 12;

// TD token bits (Linux TD_TOKEN_*): PID 7:0, device 14:8, endpoint
// 18:15, data toggle 19, expected length (len - 1) 31:21.
const TD_TOKEN_EXPLEN_SHIFT: u32 = 21;
/// Token length field for a zero-length TD: Linux `uhci_explen(0)`
/// encodes `(0 - 1) & 0x7FF` = 0x7FF; QEMU decodes it back as
/// `((token >> 21) + 1) & 0x7ff` = 0 bytes.
const TD_EXPLEN_ZERO: u32 = 0x7FF;

// PIDs (USB 2.0 §8.3.1 PID encoding; OSDev UHCI table: "0x69 = IN,
// 0xE1 = OUT, 0x2D = SETUP").
const PID_SETUP: u8 = 0x2D;
const PID_IN: u8 = 0x69;
const PID_OUT: u8 = 0xE1;

/// Arena layout inside one 4 KiB frame (the QH sits at offset 0 so it
/// is 16-byte aligned — QEMU fetches descriptors at `link & ~0xf`).
const ARENA_QH: usize = 0x000; // 16 bytes reserved (QH is 8)
const ARENA_TD: usize = 0x010;
/// Control transfers: setup TD + up to 32 data TDs (256 B ÷ min
/// packet 8) + status TD = 34; 36 gives head-room (matches
/// `usbwire::MAX_CONFIG_TOTAL` ÷ 8 + 2).
const MAX_TDS: usize = 36;
const ARENA_SETUP: usize = 0x280; // 8-byte SETUP staging
const ARENA_DATA: usize = 0x300; // control/interrupt data staging
/// Staging for one configuration descriptor (`usbwire::MAX_CONFIG_TOTAL`).
const DATA_BUF_LEN: usize = 256;

// --- Bounds (fail-closed: every wait is double-bounded) --------------------
/// Absolute spin cap per poll — the fallback if the PIT were dead (the
/// tick deadlines below normally fire far earlier).
const POLL_LIMIT: u32 = 5_000_000;
/// Tick deadline (PIT `HZ = 100` → 10 ticks = 100 ms) for one transfer.
const TRANSFER_TICKS: u64 = 20;
/// Frame-counter wait bound: one frame is 1 ms; 5 ticks = 50 ms.
const FRAME_TICKS: u64 = 5;
/// HCRESET self-clear and post-reset/start waits: 50 ms each (the USB
/// reset-signaling minimum is 10 ms; 50 clears it with margin).
const RESET_TICKS: u64 = 5;
/// Port-reset hold and post-enable settle (USB 2.0 port-reset recovery
/// is milliseconds; 50 ms each is generous and bounded).
const PORT_RESET_TICKS: u64 = 5;
const PORT_SETTLE_TICKS: u64 = 5;

/// Translated set-1 bytes waiting for `keyboard.rs` to drain: one boot
/// report is at most `Translator::MAX_BYTES` (36), so 64 holds a report
/// plus head-room; overflow drops the *newest* bytes (documented,
/// bounded — never a partial transition).
const PENDING_LEN: usize = 64;

/// Set once [`init`] configured a keyboard; keeps the shell's fast path
/// a single relaxed load when there is no USB keyboard.
static AVAILABLE: AtomicBool = AtomicBool::new(false);

/// The live controller + keyboard. Raw pointers into DMA memory shared
/// with the device — accessed through volatile reads/writes only, and
/// only from the shell's poll path (no IRQ handler touches USB:
/// `USBINTR` stays 0). `static mut` + `addr_of_mut!` mirrors
/// `keyboard::DECODER`'s documented single-consumer contract.
static mut KBD: Option<UsbKbd> = None;

// --- Register access -------------------------------------------------------

/// 16-bit port output. `crate::port` has `outb`/`outl`/`inw` but no
/// `outw`, and UHCI's registers are 16-bit words (Linux drives them
/// with `uhci_writew`); the safety contract is exactly `port::outb`'s.
///
/// # Safety
/// `port` must be the validated UHCI I/O window (from
/// [`decode_io_bar`]) and `val` a UHCI register value.
#[inline]
unsafe fn outw(port: u16, val: u16) {
    // SAFETY: forwarded to the caller's contract above; `out` touches
    // I/O space only.
    unsafe {
        core::arch::asm!(
            "out dx, ax",
            in("dx") port,
            in("ax") val,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Read one 16-bit UHCI register. `io` must be a validated UHCI I/O
/// base (everything in this module gets it from [`decode_io_bar`]).
#[inline]
fn reg_read(io: u16, off: u16) -> u16 {
    // SAFETY: `io` is the decoded BAR4 window (non-zero, fits its
    // 32-byte register range) and `off` is a register constant above;
    // 16-bit `in` matches the register width (Linux `uhci_readw`).
    // Polled, single-core — no concurrent access.
    unsafe { inw(io.wrapping_add(off)) }
}

/// Write one 16-bit UHCI register (contract of [`reg_read`]).
#[inline]
fn reg_write(io: u16, off: u16, val: u16) {
    // SAFETY: as `reg_read`; `outw`'s contract is the same port-I/O
    // contract `crate::port::outb` uses.
    unsafe { outw(io.wrapping_add(off), val) };
}

/// Decode BAR4 as an I/O base: bit0 set (I/O-space BAR, PCI Local Bus
/// Spec §6.2.1), non-zero, and the full 32-byte register window
/// (`0x00..=0x18` reaches PORTSC2) must fit in 16-bit port space.
fn decode_io_bar(bar: u32) -> Result<u16, &'static str> {
    if bar & 1 == 0 {
        return Err("BAR4 is not an I/O BAR");
    }
    let base = bar & !0x3;
    if base == 0 {
        return Err("BAR4 unassigned");
    }
    if u64::from(base) + 0x18 > 0x1_0000 {
        return Err("BAR4 window overflows 16-bit port space");
    }
    Ok(base as u16)
}

/// Disable the BIOS's legacy keyboard/mouse SMI traps (UHCI Design
/// Guide §5.2.1 LEGSUP): write the W1C status mask with every enable
/// bit cleared, then zero Intel's USBRES_INTEL wakeup byte (Linux
/// `uhci_pci_configure_hc`). Returns the readback for the log — QEMU
/// does not emulate LEGSUP (hcd-uhci.c has no `0xC0` handler; the
/// value lands in generic PCI config storage), so callers log it and
/// never assert on it.
fn disable_legacy(loc: pci::Location, vendor: u16) -> u16 {
    write32(loc, USBLEGSUP, USBLEGSUP_DISABLE);
    if vendor == 0x8086 {
        let res = read32(loc, USBRES_INTEL);
        write32(loc, USBRES_INTEL, res & !0xFF);
    }
    (read32(loc, USBLEGSUP) & 0xFFFF) as u16
}

// --- Timing ----------------------------------------------------------------

/// Sleep (bounded) for `ticks` PIT ticks: the tick deadline is the real
/// bound; `POLL_LIMIT` stops us dead if IRQ0 never fires.
fn wait_ticks(ticks: u64) {
    let deadline = crate::pit::ticks().saturating_add(ticks.max(1));
    let mut spins = 0u32;
    while crate::pit::ticks() < deadline {
        if spins > POLL_LIMIT {
            return; // PIT wedged: give up early, stay bounded
        }
        spins += 1;
        core::hint::spin_loop();
    }
}

// --- Device structures -----------------------------------------------------

/// Transfer Descriptor (16 bytes — hardware ABI, Linux `struct uhci_td`).
#[repr(C)]
#[derive(Clone, Copy)]
struct Td {
    link: u32,
    status: u32,
    token: u32,
    buffer: u32,
}

/// Queue Header (8 bytes — Linux `struct uhci_qh` hardware fields).
#[repr(C)]
#[derive(Clone, Copy)]
struct Qh {
    link: u32,
    element: u32,
}

// Layout is a hardware ABI: catch compiler surprises at compile time.
const _: () = assert!(core::mem::size_of::<Td>() == 16);
const _: () = assert!(core::mem::size_of::<Qh>() == 8);

/// One TD to schedule (everything the token/status fields need).
#[derive(Clone, Copy)]
struct TdSpec {
    addr: u8,     // device address (token bits 14:8)
    ep: u8,       // endpoint number (token bits 18:15), masked from wire
    pid: u8,      // SETUP/IN/OUT
    toggle: bool, // data toggle
    len: usize,   // payload bytes (0 = zero-length/status)
    buffer: u32,  // DMA buffer (physical address)
}

/// Result of waiting on a chain: completed, or the device NAKed (only
/// possible on the polled interrupt-IN endpoint — an idle keyboard
/// NAKs every poll, QEMU `dev-hid.c` `USB_RET_NAK`).
#[derive(Clone, Copy)]
enum Done {
    Complete,
    Nak,
}

/// Why a transfer was refused — every arm maps to a TD status bit
/// (Linux `TD_CTRL_*`), never an invented condition.
fn td_error(status: u32) -> Option<&'static str> {
    if status & TD_STALL != 0 {
        Some("endpoint stalled")
    } else if status & TD_CRCTIMEO != 0 {
        Some("CRC/timeout error")
    } else if status & TD_BABBLE != 0 {
        Some("babble detected")
    } else if status & TD_DBUFERR != 0 {
        Some("data buffer error")
    } else if status & TD_BITSTUFF != 0 {
        Some("bit-stuff error")
    } else {
        None
    }
}

/// Bytes a completed TD transferred: hardware writes `len - 1` into
/// status bits 10:0 (QEMU `uhci_complete_td`: `(len - 1) & 0x7ff`);
/// `+1` with carry-out then mask decodes a zero-length status TD back
/// to 0 (Linux `uhci_actual_length`).
fn actual_len(status: u32) -> usize {
    (status.wrapping_add(1) & TD_ACTLEN_MASK) as usize
}

fn fatal(msg: &str) -> ! {
    serial_println!("FATAL: usb: {msg}");
    crate::halt()
}

/// Hand out one physical frame as DMA memory; the identity map makes
/// phys == virt (entry.S maps the first 4 GiB and the allocator only
/// hands out frames inside it — `memory::TRACKED_BYTES`), which is
/// also what UHCI's 32-bit physical pointers need.
fn alloc_frame(msg: &'static str) -> crate::memory::Frame {
    match crate::memory::alloc() {
        Some(frame) => frame,
        None => fatal(msg),
    }
}

// --- The driver ------------------------------------------------------------

/// A probed, running UHCI controller with one enumerated boot keyboard.
///
/// Owns two DMA frames (frame list + arena) for the machine's lifetime,
/// exactly like `e1000`'s rings — never freed while the controller
/// runs.
struct UsbKbd {
    io: u16,
    /// Frame-list frame (1024 × 4 B = 4 KiB), kept for ownership.
    _fl_frame: crate::memory::Frame,
    /// Arena frame: QH + TDs + SETUP/data staging (phys == virt).
    _arena_frame: crate::memory::Frame,
    arena: *mut u8,
    /// Device address (0 until SET_ADDRESS lands).
    addr: u8,
    /// Endpoint-0 max packet size (8 until the first descriptor read).
    maxpkt0: u8,
    /// The device answered on a low-speed port (PORTSC LSDA): every
    /// TD this keyboard schedules carries [`TD_LOW_SPEED`].
    low_speed: bool,
    /// The keyboard's interrupt-IN endpoint (validated by `usbwire`).
    endpoint: usbwire::EndpointDescriptor,
    /// Interrupt pipe data toggle (DATA0 at endpoint enable, USB 2.0
    /// §5.6.3), flipped after every completed transfer.
    int_toggle: bool,
    /// HID usage → set-1 diff engine (`usbwire`).
    translator: Translator,
    /// Translated bytes waiting for `keyboard.rs`.
    pending: [u8; PENDING_LEN],
    pending_pos: usize,
    pending_len: usize,
    /// Runtime failure latch: one message, then USB input stops.
    dead: bool,
}

/// Enumeration outcome that distinguishes "some other USB device"
/// (keep searching ports) from "the bus/controller is broken"
/// (fail closed).
enum EnumErr {
    NotKeyboard,
    Broken(&'static str),
}

/// Bring one UHCI function up and enumerate a boot keyboard on it.
///
/// `Ok(Some(kbd))` — a boot keyboard is enumerated and configured.
/// `Ok(None)` — the controller is healthy but has no keyboard on any
/// port (try the next controller; on the MacBook the keyboard is on
/// the first one, `00:1d.0`).
/// `Err` — present-but-broken (bad BAR, dead controller, a device that
/// fails enumeration): the boot path fails closed.
fn bring_up(dev: &Device) -> Result<Option<UsbKbd>, &'static str> {
    let loc = dev.location;

    // Enable I/O space + bus master (PCI Local Bus Spec §6.2.1 bits;
    // DMA needs BM). Same read-modify-write pattern as `e1000`.
    let cmd = read32(loc, 0x04);
    let want = CMD_IO_SPACE | CMD_BUS_MASTER;
    write32(
        loc,
        0x04,
        (cmd & 0xFFFF_0000) | ((cmd as u16 | want) as u32),
    );
    if read32(loc, 0x04) as u16 & want != want {
        return Err("could not enable I/O space + bus master");
    }

    // BAR4 → I/O base (module docs: BAR4 is UHCI's I/O BAR).
    let io = decode_io_bar(read32(loc, IO_BAR_OFFSET))?;

    // Legacy traps off (UHCI Design Guide §5.2.1) before we touch the
    // controller or the i8042 ports the BIOS may be trapping.
    let legsup = disable_legacy(loc, dev.vendor_id);
    serial_println!("usb: {loc} I/O {io:#06x}, legsup {legsup:#06x} (legacy traps off)");

    // Reset to a known state. HCRESET (Design Guide §2.1.1) clears the
    // controller and — in QEMU — re-runs the port attach cycle
    // (`uhci_reset` → `usb_port_reset` → `uhci_attach` restores
    // `CCS|CSC`), so the attached keyboard stays visible; the device
    // itself comes back at address 0 / DEFAULT state (`usb_device_reset`,
    // hw/usb/core.c), which is what our address-0 probe relies on.
    reg_write(io, USBINTR, 0); // no USB interrupts: polled milestone
    reg_write(io, USBCMD, USBCMD_HCRESET);
    let mut spins = 0u32;
    let deadline = crate::pit::ticks().saturating_add(RESET_TICKS);
    while reg_read(io, USBCMD) & USBCMD_HCRESET != 0 {
        if spins > POLL_LIMIT || crate::pit::ticks() >= deadline {
            return Err("HCRESET never cleared");
        }
        spins += 1;
        core::hint::spin_loop();
    }
    if reg_read(io, USBSTS) & USBSTS_HCH == 0 {
        return Err("controller not halted after reset");
    }
    reg_write(io, USBSTS, USBSTS_CLEAR); // ack stale status, keep HCH

    // DMA memory: the frame list (every entry → our QH, so the
    // schedule runs every frame instead of only frame 0 of 1024) and
    // the arena (QH + TDs + staging).
    let fl_frame = alloc_frame("out of frames (UHCI frame list)");
    let arena_frame = alloc_frame("out of frames (UHCI arena)");
    // SAFETY: fresh frames from the identity-mapped allocator (phys ==
    // virt, < 4 GiB); zeroed/filled before the device can read them.
    unsafe {
        let fl = fl_frame.start_phys() as *mut u32;
        let qh_phys = arena_frame.start_phys() + ARENA_QH as u64;
        let entry = (qh_phys as u32) | LINK_QH;
        for i in 0..1024usize {
            write_volatile(fl.add(i), entry);
        }
        let arena = arena_frame.start_phys() as *mut u8;
        write_volatile(
            arena.cast::<Qh>(),
            Qh {
                link: LINK_TERM,
                element: LINK_TERM,
            },
        );
    }

    let mut kbd = UsbKbd {
        low_speed: false, // set by the port scan below, before enumeration
        io,
        _fl_frame: fl_frame,
        _arena_frame: arena_frame,
        arena: arena_frame.start_phys() as *mut u8,
        addr: 0,
        maxpkt0: 8, // USB 2.0 §9.2.6.1: the first descriptor read is 8 bytes
        endpoint: usbwire::EndpointDescriptor {
            address: 0,
            attributes: 0,
            max_packet_size: 0,
            interval: 0,
        },
        int_toggle: false,
        translator: Translator::new(),
        pending: [0; PENDING_LEN],
        pending_pos: 0,
        pending_len: 0,
        dead: false,
    };

    // Program the schedule: FRBASEADD (two 16-bit halves — QEMU's
    // `UHCI_USBFLBASEADD`/`+2` handlers and Linux's `uhci_writel`
    // both consume it this way; the frame list is 4 KiB-aligned by
    // construction), SOF modify = the spec default 64 (Linux
    // `USBSOF_DEFAULT`), then CF as the last configuration action
    // (Design Guide §2.1.1: software-only semaphore) together with
    // MAXP=64 (§2.1.1: smaller reclamation packets risk a babble in
    // the frame-end window) and RS to start the schedule.
    let fl_phys = fl_frame.start_phys();
    if fl_phys & 0xFFF != 0 {
        return Err("frame list not 4 KiB aligned");
    }
    reg_write(io, USBFLBASEADD, fl_phys as u16);
    reg_write(io, USBFLBASEADD + 2, (fl_phys >> 16) as u16);
    reg_write(io, USBSOF, 64);
    reg_write(io, USBCMD, USBCMD_MAXP | USBCMD_CF);
    reg_write(io, USBCMD, USBCMD_RS | USBCMD_MAXP | USBCMD_CF);
    let mut spins = 0u32;
    let deadline = crate::pit::ticks().saturating_add(RESET_TICKS);
    while reg_read(io, USBSTS) & USBSTS_HCH != 0 {
        if spins > POLL_LIMIT || crate::pit::ticks() >= deadline {
            return Err("controller did not start (HCH stayed set)");
        }
        spins += 1;
        core::hint::spin_loop();
    }
    serial_println!("usb: running, frame list at {fl_phys:#010x}");

    // Port scan → enumeration, one port at a time: a valid device that
    // isn't a boot keyboard moves the search on; a transfer failure is
    // controller/device breakage and fails closed.
    for port in 0..UHCI_PORTS {
        let sc = reg_read(io, PORTSC1 + 2 * port);
        // Raw status in the log first: every later decision is read
        // from this register, and the smoke log must show why a port
        // was or wasn't used (numeric only — this is a register value,
        // not device data).
        serial_println!("usb: port {port} status {sc:#06x}");
        if sc & PORT_CCS == 0 {
            continue; // nothing connected
        }
        let low_speed = sc & PORT_LSDA != 0;
        if low_speed {
            // Real keyboards are often low-speed HID (the MacBook's
            // is); enumerate them with the TD low-speed bit set.
            serial_println!("usb: port {port} low-speed device — enumerating");
        }
        kbd.low_speed = low_speed;
        // Reset the port: PR is write-triggered and read-only in
        // PORTSC (QEMU `UHCI_PORT_READ_ONLY` includes bit 9; real
        // hardware clears it itself), so: assert PR, hold 50 ms (USB
        // 2.0 needs ≥10 ms of reset signaling), then enable PE and let
        // the device settle. CSC/PEC ride along as W1C acks. The reset
        // also puts the device at address 0 / DEFAULT state
        // (`usb_device_reset`, hw/usb/core.c) — even if firmware left
        // it addressed, enumeration below starts clean.
        reg_write(io, PORTSC1 + 2 * port, PORT_PR | PORT_CSC | PORT_PEC);
        wait_ticks(PORT_RESET_TICKS);
        reg_write(io, PORTSC1 + 2 * port, PORT_PE | PORT_CSC | PORT_PEC);
        wait_ticks(PORT_SETTLE_TICKS);
        let sc = reg_read(io, PORTSC1 + 2 * port);
        if sc & PORT_CCS == 0 || sc & PORT_PE == 0 {
            serial_println!("usb: port {port} did not enable after reset ({sc:#06x})");
            continue; // no device survived — try next port
        }

        match enumerate(&mut kbd) {
            Ok((vid, pid, boot)) => {
                serial_println!(
                    "usb: boot keyboard {vid:#04x}:{pid:#04x} iface {}, ep {:#04x}",
                    boot.interface_number,
                    boot.endpoint.address
                );
                return Ok(Some(kbd));
            }
            Err(EnumErr::NotKeyboard) => {
                serial_println!("usb: port {port} device is not a boot keyboard");
                continue;
            }
            Err(EnumErr::Broken(why)) => return Err(why),
        }
    }

    // Healthy controller, no keyboard: stop the schedule before the
    // DMA frames go back to the pool (a running controller must never
    // point at freed memory), then release them.
    reg_write(io, USBCMD, USBCMD_MAXP | USBCMD_CF); // RS = 0
    crate::memory::free(kbd._fl_frame);
    crate::memory::free(kbd._arena_frame);
    Ok(None)
}

/// Full enumeration + configuration of the boot keyboard (the port is
/// already reset/ready). Fails closed on any transfer error; returns
/// [`EnumErr::NotKeyboard`] only when a *valid* device answers but
/// isn't a HID boot keyboard.
fn enumerate(kbd: &mut UsbKbd) -> Result<(u16, u16, BootKeyboard), EnumErr> {
    // Fresh start per port (a previous port's failed/partial
    // enumeration must not leak its address or packet size).
    kbd.addr = 0;
    kbd.maxpkt0 = 8;
    kbd.int_toggle = false;

    // 1. First 8 bytes at address 0 (USB 2.0 §9.2.6.1) → bMaxPacketSize0.
    let mut probe = [0u8; 8];
    let got = kbd
        .control_in(&setup(0x80, 0x06, 0x0100, 0, 8), &mut probe)
        .map_err(EnumErr::Broken)?;
    if got != 8 || probe[0] != 18 || probe[1] != 0x01 {
        return Err(EnumErr::Broken("device descriptor header invalid"));
    }
    let max0 = probe[7];
    if !matches!(max0, 8 | 16 | 32 | 64) {
        return Err(EnumErr::Broken("illegal bMaxPacketSize0"));
    }

    // 2. SET_ADDRESS 1 — its status stage still travels to address 0
    // (the device switches when the transfer completes).
    kbd.control_out(&setup(0x00, 0x05, 1, 0, 0))
        .map_err(EnumErr::Broken)?;
    kbd.addr = 1;
    kbd.maxpkt0 = max0;

    // 3. Full device descriptor (18 bytes) — `usbwire` validates it.
    let mut dev = [0u8; 18];
    let got = kbd
        .control_in(&setup(0x80, 0x06, 0x0100, 0, 18), &mut dev)
        .map_err(EnumErr::Broken)?;
    if got != 18 {
        return Err(EnumErr::Broken("short device descriptor"));
    }
    if dev[..8] != probe[..8] {
        return Err(EnumErr::Broken("device descriptor changed between reads"));
    }
    let dd = parse_device(&dev).map_err(|e| {
        serial_println!("usb: device descriptor refused: {e:?}");
        EnumErr::Broken("device descriptor refused")
    })?;

    // 4. Configuration descriptor: header first (wTotalLength), then
    // the whole thing — every length bounds-checked before use.
    let mut head = [0u8; 9];
    let got = kbd
        .control_in(&setup(0x80, 0x06, 0x0200, 0, 9), &mut head)
        .map_err(EnumErr::Broken)?;
    if got != 9 {
        return Err(EnumErr::Broken("short configuration header"));
    }
    let total = u16::from_le_bytes([head[2], head[3]]) as usize;
    if !(9..=DATA_BUF_LEN).contains(&total) {
        return Err(EnumErr::Broken("implausible wTotalLength"));
    }
    let mut cfg = [0u8; DATA_BUF_LEN];
    let got = kbd
        .control_in(
            &setup(0x80, 0x06, 0x0200, 0, total as u16),
            &mut cfg[..total],
        )
        .map_err(EnumErr::Broken)?;
    if got != total {
        return Err(EnumErr::Broken("short configuration descriptor"));
    }
    let boot = find_boot_keyboard(&cfg[..total]).map_err(|e| match e {
        // A well-formed device that simply isn't a boot keyboard
        // (mouse, storage, …): not fatal, keep searching ports.
        usbwire::Error::NotBootKeyboard => EnumErr::NotKeyboard,
        // Structurally wrong for a device claiming to be our keyboard:
        // fail closed rather than drive garbage.
        other => {
            serial_println!("usb: config descriptor refused: {other:?}");
            EnumErr::Broken("boot-keyboard config refused")
        }
    })?;

    // 5. Configure: SET_CONFIGURATION, then HID boot protocol +
    // infinite idle (HID 1.11 §7.2.4 Set_Protocol boot = 0,
    // §7.2.2 Set_Idle 0; bmRequestType 0x21 = host-to-device, class,
    // interface).
    kbd.control_out(&setup(0x00, 0x09, boot.config_value as u16, 0, 0))
        .map_err(EnumErr::Broken)?;
    kbd.control_out(&setup(0x21, 0x0B, 0, boot.interface_number as u16, 0))
        .map_err(EnumErr::Broken)?;
    kbd.control_out(&setup(0x21, 0x0A, 0, boot.interface_number as u16, 0))
        .map_err(EnumErr::Broken)?;

    kbd.endpoint = boot.endpoint;
    kbd.int_toggle = false; // DATA0 at endpoint enable (USB 2.0 §5.6.3)
    Ok((dd.vendor_id, dd.product_id, boot))
}

impl UsbKbd {
    fn td_ptr(&self, i: usize) -> *mut Td {
        // SAFETY: arena is a fresh 4 KiB frame; ARENA_TD + i*16 with
        // i < MAX_TDS stays inside it (0x10 + 36*16 = 0x250 < 0x400).
        unsafe { self.arena.add(ARENA_TD + i * 16).cast() }
    }

    fn td_phys(&self, i: usize) -> u32 {
        // Identity map: the arena's virtual address *is* its physical
        // address (entry.S); allocator frames live below 4 GiB, so the
        // u32 truncation cannot lose bits (UHCI pointers are 32-bit).
        (self.arena as u64 + (ARENA_TD + i * 16) as u64) as u32
    }

    fn setup_phys(&self) -> u32 {
        // Identity map, as `td_phys` — arena offset inside the frame.
        (self.arena as u64 + ARENA_SETUP as u64) as u32
    }

    fn data_phys(&self) -> u32 {
        // Identity map, as `td_phys` — arena offset inside the frame.
        (self.arena as u64 + ARENA_DATA as u64) as u32
    }

    fn qh(&self) -> *mut Qh {
        self.arena.cast()
    }

    /// Wait (bounded) for the frame counter to advance — proof the
    /// controller is ticking, and the barrier that guarantees no frame
    /// is still fetching the *previous* chain while we rewrite TDs
    /// (without it, real hardware could DMA through a half-written
    /// buffer pointer).
    fn wait_frame(&self) -> Result<(), &'static str> {
        let start = reg_read(self.io, FRNUM) & 0x7FF;
        let deadline = crate::pit::ticks().saturating_add(FRAME_TICKS);
        let mut spins = 0u32;
        loop {
            if reg_read(self.io, FRNUM) & 0x7FF != start {
                return Ok(());
            }
            if spins > POLL_LIMIT || crate::pit::ticks() >= deadline {
                return Err("frame counter not advancing (controller dead?)");
            }
            spins += 1;
            core::hint::spin_loop();
        }
    }

    /// Schedule `specs` as one chain under the permanent QH, poll the
    /// last TD to completion (bounded), then unlink. `allow_nak`
    /// returns [`Done::Nak`] while the device keeps NAKing (idle
    /// interrupt-IN); control transfers never NAK and wait it out.
    ///
    /// # Safety contract
    /// Every `specs[i].buffer` must be DMA-capable memory this driver
    /// owns for `specs[i].len` bytes — all callers stage inside this
    /// arena frame.
    fn run_specs(&mut self, specs: &[TdSpec], allow_nak: bool) -> Result<Done, &'static str> {
        if specs.is_empty() || specs.len() > MAX_TDS {
            return Err("bad transfer descriptor count");
        }
        // No in-flight fetch may overlap the TD writes below.
        self.wait_frame()?;

        let n = specs.len();
        for (i, s) in specs.iter().enumerate() {
            let link = if i + 1 < n {
                self.td_phys(i + 1)
            } else {
                LINK_TERM
            };
            let explen = if s.len == 0 {
                TD_EXPLEN_ZERO
            } else {
                (s.len as u32 - 1) & 0x7FF
            };
            let token = u32::from(s.pid)
                | (u32::from(s.addr & 0x7F) << 8)
                | (u32::from(s.ep & 0x0F) << 15)
                | ((s.toggle as u32) << 19)
                | (explen << TD_TOKEN_EXPLEN_SHIFT)
                | if self.low_speed { TD_LOW_SPEED } else { 0 };
            let td = Td {
                link,
                status: TD_ACTIVE | TD_CERR3,
                token,
                buffer: s.buffer,
            };
            // SAFETY: slot i < MAX_TDS inside the arena frame (`td_ptr`);
            // volatile because the device updates `status` by DMA and we
            // must observe it exactly as written.
            unsafe { write_volatile(self.td_ptr(i), td) };
        }
        // Descriptors must hit memory before the QH publishes them.
        fence(Ordering::SeqCst);

        // SAFETY: the QH lives at the arena base (16-byte aligned, as
        // QEMU's `link & ~0xf` fetch requires); element points at TD 0
        // (type bits 00 — its physical address is 16-aligned).
        unsafe {
            write_volatile(
                self.qh(),
                Qh {
                    link: LINK_TERM,
                    element: self.td_phys(0),
                },
            )
        };
        fence(Ordering::SeqCst);

        let done = self.wait_td(n, allow_nak);

        // Unlink before anything is rewritten: the next chain's
        // `wait_frame` then proves no fetch is in flight.
        // SAFETY: as above — restoring the idle (terminated) state.
        unsafe {
            write_volatile(
                self.qh(),
                Qh {
                    link: LINK_TERM,
                    element: LINK_TERM,
                },
            )
        };
        fence(Ordering::SeqCst);
        done
    }

    /// Bounded poll of the chain's last TD: completion (checking the
    /// error bits of *every* TD on timeout — an early stall stops the
    /// chain, so later TDs would never run), or NAK when allowed.
    fn wait_td(&self, n: usize, allow_nak: bool) -> Result<Done, &'static str> {
        let deadline = crate::pit::ticks().saturating_add(TRANSFER_TICKS);
        let mut spins = 0u32;
        loop {
            // SAFETY: our TD ring; `status` is device-owned DMA output
            // (volatile read — the e1000 descriptor-poll pattern).
            let st = unsafe { read_volatile(self.td_ptr(n - 1)) }.status;
            if st & TD_ACTIVE == 0 {
                if let Some(e) = td_error(st) {
                    return Err(e);
                }
                return Ok(Done::Complete);
            }
            if allow_nak && st & TD_NAK != 0 {
                return Ok(Done::Nak);
            }
            if spins > POLL_LIMIT || crate::pit::ticks() >= deadline {
                // Diagnose the real culprit: a mid-chain error leaves
                // later TDs active forever.
                for i in 0..n {
                    // SAFETY: as above, read-only scan of our ring.
                    let st = unsafe { read_volatile(self.td_ptr(i)) }.status;
                    if st & TD_ACTIVE == 0
                        && let Some(e) = td_error(st)
                    {
                        return Err(e);
                    }
                }
                return Err("transfer never completed (schedule not running?)");
            }
            spins += 1;
            core::hint::spin_loop();
        }
    }

    /// Control transfer with a data stage (GET_DESCRIPTOR): SETUP →
    /// `out.len()` IN TDs split at `maxpkt0` → status OUT. Returns the
    /// bytes the device actually sent (a short read is *not* an error
    /// here — the parser refuses it downstream, fail-closed).
    fn control_in(&mut self, pkt: &[u8; 8], out: &mut [u8]) -> Result<usize, &'static str> {
        if out.is_empty() || out.len() > DATA_BUF_LEN {
            return Err("control-in buffer out of bounds");
        }
        let maxp = usize::from(self.maxpkt0);
        let n_data = out.len().div_ceil(maxp);
        if n_data + 2 > MAX_TDS {
            return Err("control-in needs too many TDs");
        }

        // SAFETY: staging area inside our arena frame; 8 ≤ DATA_BUF_LEN.
        unsafe {
            core::ptr::copy_nonoverlapping(pkt.as_ptr(), self.arena.add(ARENA_SETUP), 8);
        }

        let mut specs = [TdSpec {
            addr: self.addr,
            ep: 0,
            pid: PID_SETUP,
            toggle: false,
            len: 8,
            buffer: 0,
        }; MAX_TDS];
        specs[0].buffer = self.setup_phys();
        let mut n = 1usize;
        let mut off = 0usize;
        while off < out.len() {
            let chunk = core::cmp::min(maxp, out.len() - off);
            specs[n] = TdSpec {
                addr: self.addr,
                ep: 0,
                pid: PID_IN,
                // Data stage starts at DATA1 (USB 2.0 §8.5.3), alternating.
                toggle: (n - 1).is_multiple_of(2),
                len: chunk,
                buffer: self.data_phys() + off as u32,
            };
            off += chunk;
            n += 1;
        }
        specs[n] = TdSpec {
            addr: self.addr,
            ep: 0,
            pid: PID_OUT,
            toggle: true, // status stage is always DATA1
            len: 0,
            buffer: self.setup_phys(),
        };
        self.run_specs(&specs[..=n], false)?;

        // Collect the real byte count (short packets are legal).
        let mut got = 0usize;
        for i in 1..=n_data {
            // SAFETY: our TD ring, post-completion read.
            let st = unsafe { read_volatile(self.td_ptr(i)) }.status;
            got += actual_len(st);
        }
        let got = core::cmp::min(got, out.len());
        // SAFETY: `got <= out.len() <= DATA_BUF_LEN`, so the copy stays
        // inside the arena's data area; the completion fence above
        // orders the device's DMA writes before this read.
        unsafe {
            core::ptr::copy_nonoverlapping(self.arena.add(ARENA_DATA), out.as_mut_ptr(), got);
        }
        Ok(got)
    }

    /// Control transfer without a data stage (SET_ADDRESS /
    /// SET_CONFIGURATION / SET_IDLE / SET_PROTOCOL): SETUP → status IN.
    fn control_out(&mut self, pkt: &[u8; 8]) -> Result<(), &'static str> {
        // SAFETY: as `control_in` — staging inside our arena frame.
        unsafe {
            core::ptr::copy_nonoverlapping(pkt.as_ptr(), self.arena.add(ARENA_SETUP), 8);
        }
        let specs = [
            TdSpec {
                addr: self.addr,
                ep: 0,
                pid: PID_SETUP,
                toggle: false,
                len: 8,
                buffer: self.setup_phys(),
            },
            TdSpec {
                addr: self.addr,
                ep: 0,
                pid: PID_IN,
                toggle: true, // status stage is always DATA1
                len: 0,
                buffer: self.data_phys(),
            },
        ];
        self.run_specs(&specs, false)?;
        Ok(())
    }

    /// One polled interrupt-IN transfer on the keyboard endpoint.
    /// `Ok(Some(report))` — 8 bytes received (HID boot report);
    /// `Ok(None)` — device NAKed (idle, nothing pressed);
    /// `Err` — schedule/device failure (caller decides fatal vs. latch).
    fn poll_interrupt(&mut self) -> Result<Option<[u8; 8]>, &'static str> {
        let spec = TdSpec {
            addr: self.addr,
            ep: self.endpoint.address & 0x0F,
            pid: PID_IN,
            toggle: self.int_toggle,
            len: usize::from(self.endpoint.max_packet_size),
            buffer: self.data_phys(),
        };
        match self.run_specs(core::slice::from_ref(&spec), true)? {
            Done::Nak => Ok(None),
            Done::Complete => {
                // SAFETY: our TD ring, post-completion read.
                let st = unsafe { read_volatile(self.td_ptr(0)) }.status;
                let got = actual_len(st);
                if got != usbwire::BOOT_REPORT_LEN {
                    // HID 1.11 §7.1 fixes the boot report at 8 bytes;
                    // anything else means we are not talking to one.
                    return Err("interrupt transfer was not an 8-byte boot report");
                }
                let mut report = [0u8; usbwire::BOOT_REPORT_LEN];
                // SAFETY: data staging inside the arena frame; `got == 8`
                // ≤ DATA_BUF_LEN, ordered by the completion fence.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.arena.add(ARENA_DATA),
                        report.as_mut_ptr(),
                        usbwire::BOOT_REPORT_LEN,
                    );
                }
                self.int_toggle = !self.int_toggle;
                Ok(Some(report))
            }
        }
    }

    /// Move a translated report into the pending byte queue (bounded:
    /// the newest bytes are dropped on overflow — never a partial
    /// transition, `usbwire` commits atomically).
    fn enqueue(&mut self, raw: &[u8; 8]) -> Result<(), &'static str> {
        let report = parse_boot_report(raw).map_err(|_| "malformed boot report")?;
        let mut buf = [0u8; Translator::MAX_BYTES];
        let n = self
            .translator
            .translate(&report, &mut buf)
            .map_err(|_| "translation buffer too small")?;
        let space = PENDING_LEN - self.pending_len;
        let take = core::cmp::min(n, space);
        self.pending[self.pending_len..self.pending_len + take].copy_from_slice(&buf[..take]);
        self.pending_len += take;
        Ok(())
    }

    /// One pump step: while bytes are pending, drain those first;
    /// otherwise poll one interrupt-IN transfer and enqueue a fresh
    /// report. Errors propagate (caller latches `dead`).
    fn pump(&mut self) -> Result<(), &'static str> {
        if self.pending_pos < self.pending_len {
            return Ok(());
        }
        self.pending_pos = 0;
        self.pending_len = 0;
        let Some(raw) = self.poll_interrupt()? else {
            return Ok(()); // NAK: idle keyboard
        };
        self.enqueue(&raw)
    }
}

/// Build an 8-byte SETUP packet (USB 2.0 §9.3: bmRequestType,
/// bRequest, wValue, wIndex, wLength — all little-endian).
fn setup(bm: u8, request: u8, value: u16, index: u16, length: u16) -> [u8; 8] {
    [
        bm,
        request,
        value as u8,
        (value >> 8) as u8,
        index as u8,
        (index >> 8) as u8,
        length as u8,
        (length >> 8) as u8,
    ]
}

/// Entry point (called from `kernel_main` right after `PCI_OK`).
///
/// - **No UHCI in the scan** → returns silently, printing nothing:
///   the QEMU default (before xtask added `-usb -device usb-kbd`) and
///   the smoke's marker chain stay untouched.
/// - **UHCI present** → full bring-up; a broken controller, or a UHCI
///   with no boot keyboard anywhere, is `FATAL: usb: …` + `halt()`
///   (present-but-broken fails closed, `e1000` discipline).
/// - **Success** → `USB_KBD_OK`, machine-checked by `cargo xtask smoke`
///   between `PCI_OK` and `E1000_OK`.
pub fn init(scan: &Scan) {
    let mut found_uhci = false;
    for dev in scan.devices.iter().flatten() {
        if dev.class != UHCI_CLASS || dev.subclass != UHCI_SUBCLASS || dev.prog_if != UHCI_PROG_IF {
            continue;
        }
        found_uhci = true;
        serial_println!(
            "usb: UHCI at {} ({:04x}:{:04x})",
            dev.location,
            dev.vendor_id,
            dev.device_id
        );
        match bring_up(dev) {
            Ok(Some(mut kbd)) => {
                // Boot-phase proof that the *interrupt* schedule runs
                // too: QEMU's usb-kbd NAKs an idle endpoint (dev-hid.c
                // `USB_RET_NAK`), which sets the TD's NAK bit — a live
                // schedule, no key needed. A timeout or error here is
                // present-but-broken: fail closed before the marker.
                match kbd.poll_interrupt() {
                    Ok(None) => serial_println!("usb: interrupt-IN NAKs at idle (schedule live)"),
                    Ok(Some(raw)) => {
                        // A key was already down at boot: translate it
                        // into the queue (the same path the shell drains).
                        if let Err(why) = kbd.enqueue(&raw) {
                            fatal(why);
                        }
                        serial_println!("usb: interrupt-IN delivered a boot report at idle");
                    }
                    Err(why) => fatal(why),
                }
                // SAFETY: single-threaded boot path; `AVAILABLE` gates
                // every later access and no IRQ handler touches USB
                // (USBINTR = 0). Stored exactly once.
                unsafe { *core::ptr::addr_of_mut!(KBD) = Some(kbd) };
                AVAILABLE.store(true, Ordering::Relaxed);
                serial_println!("USB_KBD_OK"); // machine-checked by `cargo xtask smoke`
                return;
            }
            Ok(None) => continue, // healthy, no keyboard: try next UHCI
            Err(why) => {
                // A controller/transfer failure must not strand the
                // machine: without a serial port the only way out is
                // the power button, so USB problems degrade to a
                // warning (the keyboard simply stays unavailable).
                serial_println!("usb: enumeration failed (continuing without a keyboard): {why}");
            }
        }
    }
    if found_uhci {
        // Not fatal: a machine without a usable HID keyboard (e.g. the
        // MacBook during bring-up) must still reach the network/sshd.
        // The QEMU smoke's USB_KBD_OK still only appears when a
        // keyboard really enumerated.
        serial_println!("usb: no HID boot keyboard enumerated (continuing)");
    }
    // No UHCI at all: silent no-op (documented in the module header).
}

/// Pump one step of the USB keyboard (poll one interrupt-IN transfer
/// when the queue is empty). Called from `keyboard::poll_decoded`
/// *alongside* the i8042 path (module header: QEMU's dispatch is
/// unicast, so a keystroke arrives via exactly one of the two wires).
/// Runtime failures print one line and latch the keyboard off —
/// the boot already proved the path; a hot glitch must not `halt()`
/// the shell.
pub fn poll() {
    if !AVAILABLE.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: single consumer (the shell's keyboard poll, never an IRQ
    // handler — USBINTR stays 0), stored once by `init` before
    // `AVAILABLE` was set; `addr_of_mut!` avoids a direct reference to
    // the `static mut`.
    let kbd = unsafe { (*core::ptr::addr_of_mut!(KBD)).as_mut() };
    let Some(kbd) = kbd else {
        return;
    };
    if kbd.dead {
        return;
    }
    if let Err(why) = kbd.pump() {
        serial_println!("usb: keyboard disabled ({why})");
        kbd.dead = true;
    }
}

/// Pop one translated set-1 scancode byte for `keyboard.rs`'s
/// decoder. `None` = nothing pending this iteration (same contract as
/// the PS/2 byte feed).
pub fn next_scancode() -> Option<u8> {
    if !AVAILABLE.load(Ordering::Relaxed) {
        return None;
    }
    // SAFETY: as `poll` — single consumer, polled, no IRQ handler.
    let kbd = unsafe { (*core::ptr::addr_of_mut!(KBD)).as_mut() }?;
    if kbd.dead || kbd.pending_pos >= kbd.pending_len {
        return None;
    }
    let byte = kbd.pending[kbd.pending_pos];
    kbd.pending_pos += 1;
    Some(byte)
}
