//! Pure USB descriptor + HID boot-keyboard wire logic — the codec half
//! of the UHCI/HID keyboard milestone (docs/hardware.md §2.7 step 7).
//!
//! This crate holds everything about USB enumeration and boot-keyboard
//! input that can be decided without touching hardware: device and
//! configuration descriptor parsing (with fail-closed length
//! validation), the boot-protocol 8-byte report layout, and the
//! HID-usage → scan-code-set-1 translation table so the kernel's
//! existing set-1 decoder (`kernel/src/keyboard.rs`, `pc-keyboard`)
//! stays the single source of truth for key decoding. The UHCI register
//! and DMA `unsafe` glue lives in `kernel/src/usb.rs` (the project's
//! `unsafe` budget rule).
//!
//! **Scope — documented, deliberate limits:**
//!
//! - **Boot protocol only.** The HID *report descriptor* is never
//!   parsed (its declared length is validated and carried, not
//!   consumed): the boot interface fixes the report at 8 bytes —
//!   modifier byte, reserved byte, six usage-ID slots (HID 1.11 §7.1).
//!   A full report-descriptor parser is a later milestone.
//! - **One configuration descriptor buffer** at a time, bounded by the
//!   caller's slice; no `alloc`.
//! - **US-layout-oriented translation**: every usage this crate emits a
//!   scancode for is traceable to the sources below; anything else
//!   (F13+, media keys, PrintScreen/Pause multi-byte sequences,
//!   non-US keys) is dropped, never guessed.
//!
//! **Sources — no code here is remembered or invented:**
//!
//! - **USB 2.0 specification** (usb.org, `usb_20.pdf`): device
//!   descriptor §9.6.1 (bcdUSB release numbers, bMaxPacketSize0 ∈
//!   {8,16,32,64} full-speed), configuration descriptor §9.6.3
//!   (wTotalLength), endpoint descriptor §9.6.6 (bmAttributes bits
//!   1:0 transfer type, bInterval 1..255 full-speed).
//! - **HID 1.11 specification** (`HID1_11.pdf`): HID class descriptor
//!   §6.2.1 (bLength = 6 + 3×bNumDescriptors, report descriptor
//!   length), boot interface protocol §7.1 (8-byte keyboard report,
//!   modifier byte bit order, ErrorRollOver 0x01/POSTFail
//!   0x02/ErrorUndefined 0x03), Set_Protocol §7.2.4 (boot = 0).
//! - **USB HID Usage Tables 1.21** (usb.org, `HUT1_21.pdf`) §10
//!   *Keyboard/Keypad page (0x07)*: every usage ID in
//!   [`usage_to_set1`] (0x04='A' … 0x63=Keypad ., 0xE0..0xE7 = LCtrl
//!   … RGui), and the modifier-byte bit order used by
//!   [`BootReport::modifiers`].
//! - **Scan code set 1**: the repo's own `docs/hardware.md` §2.4 (which
//!   cites OSDev "Scan Code Set 1") — every set-1 make code this crate
//!   emits appears in that table or its "Extended (E0) keys" list
//!   (`E0 47` Home … `E0 53` Delete, `E0 1C` keypad Enter, `E0 35`
//!   keypad /, `E0 1D` RCtrl, `E0 38` RAlt, `E0 5B` LWin, `E0 5C`
//!   RWin). Break = make OR 0x80 (§2.4).
//! - **QEMU v10.0.0** `hw/usb/dev-hid.c`: the reference boot-keyboard
//!   shape the tests are built from — interface class 3 / subclass 1
//!   (boot) / protocol 1 (keyboard), HID descriptor with a 63-byte
//!   report descriptor, endpoint `0x81` interrupt-IN, wMaxPacketSize 8,
//!   bInterval 10, device descriptor `bcdUSB 0x0100`,
//!   bMaxPacketSize0 8.
//!
//! Dependency-policy note (recorded in the commit): this is wire
//! parsing over documented specs, not cryptography, so it is written
//! from scratch under exception (a) — there is no maintained `no_std`
//! USB descriptor crate (verified by search: `usb-device`/`usb-device`
//! ecosystem targets device stacks, `deser-hid`/`hid-report-parser`
//! parse report descriptors, none parse host-side configuration
//! descriptors fail-closed without `alloc`). Zero dependencies,
//! `no_std`, `forbid(unsafe_code)`, adversarially host-tested in
//! `tests/hostile.rs`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

// ---------------------------------------------------------------------------
// Errors — every one of these is a refusal, never a panic
// ---------------------------------------------------------------------------

/// Why a parse or translation refused. All failures are `Err`s on
/// wire-data grounds; nothing here can be triggered by a well-formed
/// boot keyboard we actually support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The buffer ends before a length field, descriptor or report it
    /// declared (truncation is never padded or ignored).
    Truncated,
    /// A length/type/field is structurally invalid: `bLength` that
    /// cannot describe its descriptor, a zero size, an illegal
    /// bMaxPacketSize0, a wTotalLength that contradicts the walk, …
    Malformed,
    /// No interface is a HID boot *keyboard* (class 3, subclass 1,
    /// protocol 1) — including when the interface claims to be one but
    /// carries no HID descriptor (that case is [`Error::Malformed`]).
    NotBootKeyboard,
    /// The boot-keyboard interface has no interrupt-IN endpoint (zero
    /// endpoints, or endpoints that are interrupt-OUT / bulk / control).
    NoInterruptIn,
    /// The caller's output slice is smaller than the worst-case
    /// translation of one report (see [`Translator::MAX_BYTES`]); the
    /// translator's state is left **unchanged** so a retry with a big
    /// enough buffer emits the full transition.
    BufferTooSmall,
}

// ---------------------------------------------------------------------------
// Device descriptor (USB 2.0 §9.6.1)
// ---------------------------------------------------------------------------

/// Decoded device descriptor (18 bytes, `bLength` must be exactly 18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceDescriptor {
    /// bcdUSB — USB release the device complies with (BCD).
    pub bcd_usb: u16,
    /// bDeviceClass (0 = per-interface classes, the keyboard case).
    pub device_class: u8,
    /// bDeviceSubClass.
    pub device_subclass: u8,
    /// bDeviceProtocol.
    pub device_protocol: u8,
    /// bMaxPacketSize0 — endpoint-0 packet size (8/16/32/64 full-speed).
    pub max_packet_size0: u8,
    /// idVendor.
    pub vendor_id: u16,
    /// idProduct.
    pub product_id: u16,
    /// bcdDevice (device release number, BCD).
    pub bcd_device: u16,
    /// bNumConfigurations (validated ≥ 1).
    pub num_configurations: u8,
}

/// Length of a device descriptor (USB 2.0 §9.6.1: `bLength` = 18).
pub const DEVICE_DESCRIPTOR_LEN: usize = 18;

/// Parse an 18-byte device descriptor. Fail-closed: `bLength` and
/// `bDescriptorType` must be exactly right, `bcdUSB` must name a real
/// USB release (major 1..=3), `bMaxPacketSize0` must be one of the
/// full-speed legal sizes, and at least one configuration must exist.
pub fn parse_device(buf: &[u8]) -> Result<DeviceDescriptor, Error> {
    if buf.len() < DEVICE_DESCRIPTOR_LEN {
        return Err(Error::Truncated);
    }
    if buf[0] as usize != DEVICE_DESCRIPTOR_LEN {
        return Err(Error::Malformed); // USB 2.0 §9.6.1: bLength = 18
    }
    if buf[1] != 0x01 {
        return Err(Error::Malformed); // DEVICE descriptor type
    }
    let bcd_usb = u16::from_le_bytes([buf[2], buf[3]]);
    // bcdUSB major = high BCD digit: USB 1.x/2.x/3.x are the only
    // releases (USB 2.0 §9.6.2.1). 0x00xx is not a release number.
    let major = (bcd_usb >> 8) & 0xFF;
    if !(1..=3).contains(&major) {
        return Err(Error::Malformed);
    }
    let max_packet_size0 = buf[7];
    // USB 2.0 §9.6.2.1: full-speed endpoint 0 is 8, 16, 32 or 64.
    // (Low-speed 8 is the same set; UHCI handles both.)
    if !matches!(max_packet_size0, 8 | 16 | 32 | 64) {
        return Err(Error::Malformed);
    }
    let num_configurations = buf[17];
    if num_configurations == 0 {
        return Err(Error::Malformed);
    }
    Ok(DeviceDescriptor {
        bcd_usb,
        device_class: buf[4],
        device_subclass: buf[5],
        device_protocol: buf[6],
        max_packet_size0,
        vendor_id: u16::from_le_bytes([buf[8], buf[9]]),
        product_id: u16::from_le_bytes([buf[10], buf[11]]),
        bcd_device: u16::from_le_bytes([buf[12], buf[13]]),
        num_configurations,
    })
}

// ---------------------------------------------------------------------------
// Configuration descriptor walk (USB 2.0 §9.6.3, HID 1.11 §6.2.1)
// ---------------------------------------------------------------------------

/// Transfer-type field (bmAttributes bits 1:0): interrupt = 3
/// (USB 2.0 §9.6.6).
pub const TRANSFER_INTERRUPT: u8 = 0b11;
/// Endpoint direction bit (bEndpointAddress bit 7): IN = 1 (USB 2.0
/// §9.6.6).
pub const DIR_IN: u8 = 0x80;

/// One endpoint descriptor (7 bytes, `bLength` must be exactly 7 —
/// the 9-byte audio variant is refused, this is a keyboard stack).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointDescriptor {
    /// bEndpointAddress: number (bits 3:0) + direction (bit 7).
    pub address: u8,
    /// bmAttributes (bits 1:0 = transfer type).
    pub attributes: u8,
    /// wMaxPacketSize (bits 10:0; bits 15:11 must be zero — see walk).
    pub max_packet_size: u16,
    /// bInterval (frames; 1..=255 for full-speed).
    pub interval: u8,
}

impl EndpointDescriptor {
    /// True for an interrupt-IN endpoint (`bmAttributes` transfer type
    /// interrupt, direction IN).
    pub fn is_interrupt_in(&self) -> bool {
        self.attributes & 0b11 == TRANSFER_INTERRUPT && self.address & DIR_IN != 0
    }
}

/// Decoded HID class descriptor (HID 1.11 §6.2.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidDescriptor {
    /// bcdHID (BCD).
    pub bcd_hid: u16,
    /// wDescriptorLength of the **report** descriptor (declared, never
    /// fetched or parsed by this crate — boot protocol only).
    pub report_descriptor_length: u16,
}

/// The one interface + endpoint the UHCI driver configures: a HID boot
/// keyboard's interrupt-IN pipe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootKeyboard {
    /// bConfigurationValue of the configuration this came from (the
    /// value to hand to SET_CONFIGURATION; validated non-zero).
    pub config_value: u8,
    /// bInterfaceNumber (SET_PROTOCOL/SET_IDLE wIndex).
    pub interface_number: u8,
    /// The interface's interrupt-IN endpoint.
    pub endpoint: EndpointDescriptor,
    /// The interface's HID descriptor.
    pub hid: HidDescriptor,
}

/// Descriptor type constants used by the walk.
const DT_DEVICE: u8 = 0x01;
const DT_CONFIG: u8 = 0x02;
const DT_INTERFACE: u8 = 0x04;
const DT_ENDPOINT: u8 = 0x05;
const DT_HID: u8 = 0x21;
const DT_REPORT: u8 = 0x22;

/// Bound on a configuration total we will read (a boot keyboard's
/// configuration is tens of bytes; QEMU's is 34). Anything larger is
/// refused as malformed rather than buffered — our caller's buffer is
/// this size, so it is also the fail-closed cut-off, not a guess about
/// what keyboards look like.
pub const MAX_CONFIG_TOTAL: usize = 256;

/// Bound on a *declared* report-descriptor length. We never fetch the
/// report descriptor (boot protocol), so this only rejects absurd
/// declarations; QEMU's keyboard declares 63 bytes.
pub const MAX_REPORT_DESCRIPTOR_LEN: u16 = 1024;

/// Find and validate the HID boot-keyboard interface inside one
/// configuration descriptor buffer.
///
/// Contract and fail-closed rules (every one adversarially tested):
///
/// - `buf[0..9]` is the configuration header; `wTotalLength` must be
///   ≥ 9, ≤ `buf.len()` and ≤ [`MAX_CONFIG_TOTAL`]; the descriptor
///   walk consumes **exactly** `wTotalLength` bytes — a descriptor
///   that would run past it is [`Error::Truncated`], a `bLength` of
///   0/1 (infinite-loop / no-progress guard) is [`Error::Malformed`].
/// - Endpoint descriptors must be exactly 7 bytes with reserved
///   wMaxPacketSize bits clear; interface descriptors exactly 9.
/// - The selected interface must be class 3 / subclass 1 (boot) /
///   protocol 1 with `bAlternateSetting == 0`, carry a HID descriptor
///   (`bLength == 6 + 3×bNumDescriptors`, declaring a non-zero report
///   length ≤ [`MAX_REPORT_DESCRIPTOR_LEN`]), and expose an
///   interrupt-IN endpoint with wMaxPacketSize 1..=64 and bInterval
///   1..=255.
/// - Non-keyboard interfaces and their endpoints are framing-validated
///   but not semantically checked (composite devices walk through).
///
/// The HID **report descriptor itself is not consumed**: only its
/// declared length is read, which is exactly what boot protocol needs.
pub fn find_boot_keyboard(buf: &[u8]) -> Result<BootKeyboard, Error> {
    if buf.len() < 9 {
        return Err(Error::Truncated);
    }
    if buf[0] != 9 || buf[1] != DT_CONFIG {
        return Err(Error::Malformed);
    }
    let total = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if !(9..=MAX_CONFIG_TOTAL).contains(&total) {
        return Err(Error::Malformed);
    }
    if total > buf.len() {
        return Err(Error::Truncated); // wTotalLength lies beyond the buffer
    }
    let num_interfaces = buf[4];
    let config_value = buf[5];
    if num_interfaces == 0 || config_value == 0 {
        // USB 2.0 §9.6.3: bConfigurationValue 0 is reserved for the
        // unconfigured state; a configuration needs ≥ 1 interface.
        return Err(Error::Malformed);
    }

    let data = &buf[..total];

    // Candidate interfaces, in walk order. Association rule: HID and
    // endpoint descriptors belong to the most recent interface
    // descriptor (HID 1.11 §6.2.1, USB 2.0 §9.6.3).
    //
    // An interface is finalized only when it is *complete* — i.e. when
    // the next interface descriptor starts or the walk ends — so an
    // interface whose HID/endpoints come later is never judged early.
    let mut result: Option<BootKeyboard> = None;
    let mut first_error: Option<Error> = None;
    let mut cur: Option<CurIface> = None;
    let mut off = 0usize;

    while off < data.len() {
        if off + 2 > data.len() {
            return Err(Error::Truncated);
        }
        let b_length = data[off] as usize;
        let b_type = data[off + 1];
        if b_length < 2 {
            return Err(Error::Malformed); // 0 would loop forever
        }
        let end = match off.checked_add(b_length) {
            Some(e) if e <= data.len() => e,
            _ => return Err(Error::Truncated),
        };
        let desc = &data[off..end];

        match b_type {
            DT_INTERFACE => {
                if b_length != 9 {
                    return Err(Error::Malformed);
                }
                // The previous interface is complete now.
                if let Some(prev) = cur.take() {
                    finalize(prev, config_value, &mut result, &mut first_error);
                }
                cur = Some(CurIface {
                    number: desc[2],
                    alt_setting: desc[3],
                    declared_endpoints: desc[4],
                    class: desc[5],
                    subclass: desc[6],
                    protocol: desc[7],
                    hid: None,
                    endpoints: [None; MAX_ENDPOINTS_PER_INTERFACE],
                    endpoint_count: 0,
                });
            }
            DT_ENDPOINT => {
                if b_length != 7 {
                    // The 9-byte audio endpoint form has no business in
                    // a boot-keyboard configuration; refuse, don't guess.
                    return Err(Error::Malformed);
                }
                let ep = parse_endpoint(desc)?;
                let iface = cur.as_mut().ok_or(Error::Malformed)?;
                if iface.alt_setting == 0 && iface.endpoint_count < MAX_ENDPOINTS_PER_INTERFACE {
                    iface.endpoints[iface.endpoint_count] = Some(ep);
                    iface.endpoint_count += 1;
                }
            }
            DT_HID => {
                let hid = parse_hid(desc)?;
                let iface = cur.as_mut().ok_or(Error::Malformed)?;
                if iface.hid.is_none() {
                    iface.hid = Some(hid);
                }
            }
            DT_DEVICE => return Err(Error::Malformed), // device desc inside a config
            _ => {} // class/vendor descriptors: framing already validated
        }
        off = end;
    }
    // The last interface ends at the declared total.
    if let Some(last) = cur.take() {
        finalize(last, config_value, &mut result, &mut first_error);
    }

    if let Some(kbd) = result {
        return Ok(kbd);
    }
    if let Some(e) = first_error {
        return Err(e); // candidate existed but was structurally broken
    }
    Err(Error::NotBootKeyboard)
}

/// Validate one complete interface if it is a boot-keyboard candidate;
/// the first success wins, the first failure is remembered for reporting.
fn finalize(
    iface: CurIface,
    config_value: u8,
    result: &mut Option<BootKeyboard>,
    first_error: &mut Option<Error>,
) {
    if !iface.is_candidate() || result.is_some() {
        return;
    }
    match iface.finish(config_value) {
        Ok(kbd) => *result = Some(kbd),
        Err(e) => {
            if first_error.is_none() {
                *first_error = Some(e);
            }
        }
    }
}

/// Cap on interfaces we remember per configuration (walk still
/// validates *every* descriptor framing; we just stop retaining).
const MAX_ENDPOINTS_PER_INTERFACE: usize = 4;

/// One interface's collected descriptors while walking.
struct CurIface {
    number: u8,
    alt_setting: u8,
    /// bNumEndpoints — cross-checked against what the walk actually
    /// found (a lying count is refused, never silently trusted).
    declared_endpoints: u8,
    class: u8,
    subclass: u8,
    protocol: u8,
    hid: Option<HidDescriptor>,
    endpoints: [Option<EndpointDescriptor>; MAX_ENDPOINTS_PER_INTERFACE],
    endpoint_count: usize,
}

impl CurIface {
    /// A HID boot keyboard on alternate setting 0 (the boot interface
    /// has exactly one setting; HID 1.11 §7.1).
    fn is_candidate(&self) -> bool {
        self.class == 0x03
            && self.subclass == 0x01
            && self.protocol == 0x01
            && self.alt_setting == 0
    }

    /// Validate the collected descriptors into a [`BootKeyboard`].
    fn finish(&self, config_value: u8) -> Result<BootKeyboard, Error> {
        // The declared endpoint count must match the walk: a lie in
        // either direction (endpoint descriptors the interface does not
        // claim, or a claim with no descriptor) is malformed.
        if self.endpoint_count != self.declared_endpoints as usize {
            return Err(Error::Malformed);
        }
        let hid = self.hid.ok_or(Error::Malformed)?; // HID 1.11 §6.2.1
        if self.endpoint_count == 0 {
            return Err(Error::NoInterruptIn);
        }
        // First interrupt-IN endpoint wins (a boot keyboard has one).
        let ep = self.endpoints[..self.endpoint_count]
            .iter()
            .flatten()
            .find(|e| e.is_interrupt_in())
            .ok_or(Error::NoInterruptIn)?;
        // Full-speed interrupt endpoint bounds (USB 2.0 §9.6.6):
        // wMaxPacketSize 1..=64 (bits 15:11 reserved — refused in
        // `parse_endpoint`), bInterval 1..=255.
        if ep.max_packet_size == 0 || ep.max_packet_size > 64 {
            return Err(Error::Malformed);
        }
        if ep.interval == 0 {
            return Err(Error::Malformed);
        }
        Ok(BootKeyboard {
            config_value,
            interface_number: self.number,
            endpoint: *ep,
            hid,
        })
    }
}

/// Parse a 7-byte endpoint descriptor (reserved wMaxPacketSize bits
/// must be zero — bits 15:11 cover the high-speed-only
/// transactions-per-microframe field, meaningless on UHCI's full-speed
/// bus, so a set bit means we are not reading what we think).
fn parse_endpoint(desc: &[u8]) -> Result<EndpointDescriptor, Error> {
    let raw = u16::from_le_bytes([desc[4], desc[5]]);
    if raw & 0xF800 != 0 {
        return Err(Error::Malformed);
    }
    Ok(EndpointDescriptor {
        address: desc[2],
        attributes: desc[3],
        max_packet_size: raw & 0x07FF,
        interval: desc[6],
    })
}

/// Parse the HID class descriptor (HID 1.11 §6.2.1): `bLength` must
/// equal `6 + 3×bNumDescriptors`, at least one descriptor entry must
/// exist, and one of them must be the report descriptor (type 0x22)
/// with a non-zero length within [`MAX_REPORT_DESCRIPTOR_LEN`].
fn parse_hid(desc: &[u8]) -> Result<HidDescriptor, Error> {
    if desc[1] != DT_HID {
        return Err(Error::Malformed);
    }
    let num = desc[5] as usize;
    if num == 0 {
        return Err(Error::Malformed); // nothing declares a report length
    }
    let expected = 6 + 3 * num;
    if desc.len() != expected {
        return Err(Error::Malformed);
    }
    let mut report_len = 0u16;
    let mut found = false;
    for i in 0..num {
        let base = 6 + 3 * i;
        let kind = desc[base];
        let len = u16::from_le_bytes([desc[base + 1], desc[base + 2]]);
        if kind == DT_REPORT {
            report_len = len;
            found = true;
        }
    }
    if !found || report_len == 0 || report_len > MAX_REPORT_DESCRIPTOR_LEN {
        return Err(Error::Malformed);
    }
    Ok(HidDescriptor {
        bcd_hid: u16::from_le_bytes([desc[2], desc[3]]),
        report_descriptor_length: report_len,
    })
}

// ---------------------------------------------------------------------------
// Boot-protocol report (HID 1.11 §7.1)
// ---------------------------------------------------------------------------

/// Size of a boot keyboard report: modifiers + reserved + 6 key slots
/// (HID 1.11 §7.1).
pub const BOOT_REPORT_LEN: usize = 8;

/// Number of key slots in a boot report (6-key rollover).
pub const BOOT_REPORT_KEYS: usize = 6;

/// One boot-protocol keyboard report, decoded but not interpreted
/// (usage-ID → scancode translation is [`Translator`]'s job).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootReport {
    /// Modifier bitmask, HID order (HID 1.11 §7.1): bit 0 LeftCtrl,
    /// 1 LeftShift, 2 LeftAlt, 3 LeftGui, 4 RightCtrl, 5 RightShift,
    /// 6 RightAlt, 7 RightGui — i.e. bit *i* = usage `0xE0 + i`.
    pub modifiers: u8,
    /// The six usage-ID slots (`0` = empty; HID Usage Tables §10:
    /// `0x01` ErrorRollOver, `0x02` POSTFail, `0x03` ErrorUndefined).
    pub keys: [u8; BOOT_REPORT_KEYS],
    /// True when any slot carries an error code (0x01..=0x03) — the
    /// "phantom state" of a 6-key-rollover keyboard that cannot report
    /// what is pressed. The translator **refuses** such reports (no
    /// state change, no bytes) instead of treating error codes as keys.
    pub phantom: bool,
}

/// Parse exactly one 8-byte boot report. A length other than 8 is
/// refused: HID 1.11 §7.1 fixes the boot keyboard report at 8 bytes,
/// so 7 is truncation and 9+ is not a boot report.
pub fn parse_boot_report(buf: &[u8]) -> Result<BootReport, Error> {
    if buf.len() < BOOT_REPORT_LEN {
        return Err(Error::Truncated);
    }
    if buf.len() > BOOT_REPORT_LEN {
        return Err(Error::Malformed);
    }
    let mut keys = [0u8; BOOT_REPORT_KEYS];
    keys.copy_from_slice(&buf[2..BOOT_REPORT_LEN]);
    // HID 1.11 §7.1: ErrorRollOver (0x01), POSTFail (0x02) and
    // ErrorUndefined (0x03) fill the key array when the device cannot
    // report the pressed keys. Usage IDs for real keys start at 0x04
    // (HID Usage Tables §10), so 1..=3 can only be error codes.
    let phantom = keys.iter().any(|&k| (1..=3).contains(&k));
    Ok(BootReport {
        modifiers: buf[0],
        keys,
        phantom,
    })
}

// ---------------------------------------------------------------------------
// HID usage → scan code set 1 (HID Usage Tables 1.21 §10 + docs/hardware.md §2.4)
// ---------------------------------------------------------------------------

/// One set-1 make/break code: `code` is the make code; the break code
/// is `code | 0x80` (docs/hardware.md §2.4). `extended` means the
/// sequence is prefixed with `E0` (both make `E0 code` and break
/// `E0 (code|0x80)` — §2.4 "Extended (E0) keys").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Set1 {
    /// The set-1 make code (never has bit 7 set).
    pub code: u8,
    /// True when the code needs the `E0` prefix byte.
    pub extended: bool,
}

impl Set1 {
    /// The make-code byte sequence: `[E0, code]` or `[code]`.
    pub fn make_bytes(self) -> ([u8; 2], usize) {
        if self.extended {
            ([0xE0, self.code], 2)
        } else {
            ([self.code, 0], 1)
        }
    }

    /// The break-code byte sequence: `[E0, code|0x80]` or `[code|0x80]`.
    pub fn break_bytes(self) -> ([u8; 2], usize) {
        if self.extended {
            ([0xE0, self.code | 0x80], 2)
        } else {
            ([self.code | 0x80, 0], 1)
        }
    }
}

/// Translate one non-modifier keyboard usage ID (HID Usage Tables 1.21
/// §10, Keyboard/Keypad page 0x07) into its scan-code-set-1 make code
/// (docs/hardware.md §2.4, which cites OSDev "Scan Code Set 1").
///
/// Returns `None` for every usage we do not map — usage `0x00`
/// (no-event), the error codes 0x01..=0x03 (handled as phantom by
/// [`parse_boot_report`]), modifier usages 0xE0..0xE7 (see
/// [`modifier_to_set1`]), and anything outside the table (F13+,
/// PrintScreen/Pause — multi-byte sequences we deliberately drop —
/// media keys, non-US keys). Dropping is the fail-closed behaviour:
/// an unknown usage never becomes an invented scancode.
pub fn usage_to_set1(usage: u8) -> Option<Set1> {
    let (code, extended) = match usage {
        // --- Letters: HID 0x04..0x1D = A..Z, positional set-1 codes
        // (docs/hardware.md §2.4 table: a=0x1E … z=0x2C).
        0x04 => (0x1E, false), // A
        0x05 => (0x30, false), // B
        0x06 => (0x2E, false), // C
        0x07 => (0x20, false), // D
        0x08 => (0x12, false), // E
        0x09 => (0x21, false), // F
        0x0A => (0x22, false), // G
        0x0B => (0x23, false), // H
        0x0C => (0x17, false), // I
        0x0D => (0x24, false), // J
        0x0E => (0x25, false), // K
        0x0F => (0x26, false), // L
        0x10 => (0x32, false), // M
        0x11 => (0x31, false), // N
        0x12 => (0x18, false), // O
        0x13 => (0x19, false), // P
        0x14 => (0x10, false), // Q
        0x15 => (0x13, false), // R
        0x16 => (0x1F, false), // S
        0x17 => (0x14, false), // T
        0x18 => (0x16, false), // U
        0x19 => (0x2F, false), // V
        0x1A => (0x11, false), // W
        0x1B => (0x2D, false), // X
        0x1C => (0x15, false), // Y
        0x1D => (0x2C, false), // Z
        // --- Digits row: HID 0x1E..0x27 = 1..9,0 → set-1 0x02..0x0B.
        0x1E => (0x02, false), // 1
        0x1F => (0x03, false), // 2
        0x20 => (0x04, false), // 3
        0x21 => (0x05, false), // 4
        0x22 => (0x06, false), // 5
        0x23 => (0x07, false), // 6
        0x24 => (0x08, false), // 7
        0x25 => (0x09, false), // 8
        0x26 => (0x0A, false), // 9
        0x27 => (0x0B, false), // 0
        // --- Controls and punctuation (§2.4 table).
        0x28 => (0x1C, false), // Enter (main)
        0x29 => (0x01, false), // Esc
        0x2A => (0x0E, false), // Backspace
        0x2B => (0x0F, false), // Tab
        0x2C => (0x39, false), // Space
        0x2D => (0x0C, false), // -
        0x2E => (0x0D, false), // =
        0x2F => (0x1A, false), // [
        0x30 => (0x1B, false), // ]
        0x31 => (0x2B, false), // \  (US backslash)
        // 0x32 Non-US # — no set-1 code in our US-layout table: dropped.
        0x33 => (0x27, false), // ;
        0x34 => (0x28, false), // '
        0x35 => (0x29, false), // ` grave
        0x36 => (0x33, false), // ,
        0x37 => (0x34, false), // .
        0x38 => (0x35, false), // /
        // --- Locks and function keys (§2.4).
        0x39 => (0x3A, false), // CapsLock
        0x3A => (0x3B, false), // F1
        0x3B => (0x3C, false), // F2
        0x3C => (0x3D, false), // F3
        0x3D => (0x3E, false), // F4
        0x3E => (0x3F, false), // F5
        0x3F => (0x40, false), // F6
        0x40 => (0x41, false), // F7
        0x41 => (0x42, false), // F8
        0x42 => (0x43, false), // F9
        0x43 => (0x44, false), // F10
        // 0x44 F13 in some tables? — HID 1.21 §10: 0x44 = F13 is wrong;
        // 0x44 is F11? No: 0x3A..0x45 = F1..F12 (HUT §10), so:
        0x44 => (0x57, false), // F11 (§2.4: 0x57 F11)
        0x45 => (0x58, false), // F12 (§2.4: 0x58 F12)
        // 0x46 PrintScreen and 0x48 Pause are multi-byte set-1
        // sequences (E0 2A E0 37 / E1 …): deliberately dropped.
        0x47 => (0x46, false), // ScrollLock
        0x49 => (0x52, true),  // Insert   → E0 52
        0x4A => (0x47, true),  // Home     → E0 47
        0x4B => (0x49, true),  // PageUp   → E0 49
        0x4C => (0x53, true),  // Delete   → E0 53
        0x4D => (0x4F, true),  // End      → E0 4F
        0x4E => (0x51, true),  // PageDown → E0 51
        0x4F => (0x4D, true),  // Right    → E0 4D
        0x50 => (0x4B, true),  // Left     → E0 4B
        0x51 => (0x50, true),  // Down     → E0 50
        0x52 => (0x48, true),  // Up       → E0 48
        // --- Keypad (§2.4 "0x47..0x53 keypad 7..9,4..6,1..3,0,.").
        0x53 => (0x45, false), // NumLock (§2.4: 0x45 NumLock)
        0x54 => (0x35, true),  // keypad / → E0 35 (§2.4 extended list)
        0x55 => (0x37, false), // keypad * (§2.4: 0x37 keypad *)
        0x56 => (0x4A, false), // keypad -
        0x57 => (0x4E, false), // keypad +
        0x58 => (0x1C, true),  // keypad Enter → E0 1C
        0x59 => (0x4F, false), // keypad 1
        0x5A => (0x50, false), // keypad 2
        0x5B => (0x51, false), // keypad 3
        0x5C => (0x4B, false), // keypad 4
        0x5D => (0x4C, false), // keypad 5
        0x5E => (0x4D, false), // keypad 6
        0x5F => (0x47, false), // keypad 7
        0x60 => (0x48, false), // keypad 8
        0x61 => (0x49, false), // keypad 9
        0x62 => (0x52, false), // keypad 0
        0x63 => (0x53, false), // keypad .
        // 0x64 and above (power, keypad =, F13..F24, media keys, …):
        // not in docs/hardware.md §2.4 — dropped, never guessed.
        _ => return None,
    };
    Some(Set1 { code, extended })
}

/// Translate a modifier usage ID (0xE0..0xE7, HID Usage Tables §10)
/// into its set-1 code (docs/hardware.md §2.4 extended list: `E0 1D`
/// RCtrl, `E0 38` RAlt, `E0 5B` LWin, `E0 5C` RWin; base codes for
/// LCtrl 0x1D, LShift 0x2A, LAlt 0x38, RShift 0x36).
///
/// The modifier *byte* of a boot report encodes the same usages in
/// bitmask order (bit *i* = usage `0xE0 + i`), which is what
/// [`Translator`] diffs — this function exists for devices (and tests)
/// that put modifier usages in the key array instead.
pub fn modifier_to_set1(usage: u8) -> Option<Set1> {
    let (code, extended) = match usage {
        0xE0 => (0x1D, false), // LeftCtrl
        0xE1 => (0x2A, false), // LeftShift
        0xE2 => (0x38, false), // LeftAlt
        0xE3 => (0x5B, true),  // LeftGui  → E0 5B (§2.4: E0 5B LWin)
        0xE4 => (0x1D, true),  // RightCtrl → E0 1D
        0xE5 => (0x36, false), // RightShift
        0xE6 => (0x38, true),  // RightAlt → E0 38
        0xE7 => (0x5C, true),  // RightGui → E0 5C (§2.4: E0 5C RWin)
        _ => return None,
    };
    Some(Set1 { code, extended })
}

// ---------------------------------------------------------------------------
// Report → set-1 byte-stream translator (diff engine)
// ---------------------------------------------------------------------------

/// Stateful diff between consecutive boot reports: emits set-1
/// make/break bytes for keys and modifiers that **changed**, so the
/// kernel's existing set-1 decoder sees exactly the byte stream a PS/2
/// keyboard would have produced (single-consumer discipline preserved:
/// `usbwire` never decodes, it only translates).
///
/// Behaviour, all adversarially tested:
///
/// - **Phantom reports** (`BootReport::phantom`) are refused outright:
///   no state change, zero bytes — an error code is never translated
///   into a scancode, and keys held across the glitch keep their real
///   state so the next good report diffs correctly.
/// - **Unknown usages are dropped** before the diff (they never enter
///   the held set), so an unmapped key neither emits garbage nor
///   shadows a mapped one.
/// - Modifier usages carried in the key array are unioned into the
///   modifier bitmask (a device reporting LCtrl in both places still
///   produces exactly one make).
/// - Duplicated usages across slots are deduplicated (one make, one
///   break).
/// - Emit order: key breaks → modifier breaks → modifier makes → key
///   makes (release-before-press, so the decoder never sees a press
///   superseded by a stale release).
pub struct Translator {
    /// Previous report's held, mapped, non-modifier usages (deduped).
    held: [u8; BOOT_REPORT_KEYS],
    held_len: usize,
    /// Previous effective modifier bitmask (bit *i* = usage `0xE0 + i`).
    modifiers: u8,
}

impl Translator {
    /// Worst-case bytes one report can emit. The two diffs are
    /// disjoint sets, so: key breaks ≤ 6 × 2 (`E0`-prefixed worst
    /// case) = 12, key makes ≤ 12, and the 8 modifier bits split
    /// between break and make (4 of them `E0`-prefixed) = 8 + 4 = 12 →
    /// **36**. [`Translator::translate`] refuses a smaller caller
    /// buffer with [`Error::BufferTooSmall`] instead of truncating a
    /// transition.
    pub const MAX_BYTES: usize = 36;

    /// A translator that has seen no reports yet (nothing held).
    pub const fn new() -> Self {
        Translator {
            held: [0; BOOT_REPORT_KEYS],
            held_len: 0,
            modifiers: 0,
        }
    }

    /// Feed one parsed report; append the set-1 make/break byte
    /// sequence of everything that changed to `out` and return the
    /// number of bytes written.
    ///
    /// On [`Error::BufferTooSmall`] the translator's state is
    /// unchanged (the whole transition is computed before anything is
    /// committed), so the caller may retry with a bigger buffer.
    pub fn translate(&mut self, report: &BootReport, out: &mut [u8]) -> Result<usize, Error> {
        if report.phantom {
            return Ok(0); // refuse error codes: no state change, no bytes
        }

        // Effective modifier bitmask: the byte, unioned with any
        // modifier usages sitting in the key array (bit i = usage
        // 0xE0+i — HID Usage Tables §10).
        let mut modifiers = report.modifiers;
        for &k in &report.keys {
            if (0xE0..=0xE7).contains(&k) {
                modifiers |= 1 << (k - 0xE0);
            }
        }

        // New held set: mapped usages only, deduped, cap at 6 slots.
        let mut new_held = [0u8; BOOT_REPORT_KEYS];
        let mut new_len = 0usize;
        for &k in &report.keys {
            if k == 0 || (0xE0..=0xE7).contains(&k) || usage_to_set1(k).is_none() {
                continue; // empty slot, modifier, or unmapped usage
            }
            if new_held[..new_len].contains(&k) {
                continue; // duplicate slot
            }
            if new_len == BOOT_REPORT_KEYS {
                break; // cannot happen (6 slots) — belt and braces
            }
            new_held[new_len] = k;
            new_len += 1;
        }

        // Compute the whole transition into a local buffer first:
        // commit happens only if the caller's buffer fits.
        let mut tmp = [0u8; Self::MAX_BYTES];
        let mut n = 0usize;
        let mut push = |bytes: ([u8; 2], usize), n: &mut usize| -> Result<(), Error> {
            let (arr, len) = bytes;
            if *n + len > Self::MAX_BYTES {
                return Err(Error::BufferTooSmall); // unreachable by the bound above
            }
            tmp[*n..*n + len].copy_from_slice(&arr[..len]);
            *n += len;
            Ok(())
        };

        // 1. Key breaks (release-before-press).
        for &old in &self.held[..self.held_len] {
            if !new_held[..new_len].contains(&old) {
                let s = usage_to_set1(old).ok_or(Error::Malformed)?;
                push(s.break_bytes(), &mut n)?;
            }
        }
        // 2. Modifier breaks.
        for i in 0..8u8 {
            let bit = 1 << i;
            if self.modifiers & bit != 0 && modifiers & bit == 0 {
                let s = modifier_to_set1(0xE0 + i).ok_or(Error::Malformed)?;
                push(s.break_bytes(), &mut n)?;
            }
        }
        // 3. Modifier makes (modifiers before keys: Shift before 'A').
        for i in 0..8u8 {
            let bit = 1 << i;
            if self.modifiers & bit == 0 && modifiers & bit != 0 {
                let s = modifier_to_set1(0xE0 + i).ok_or(Error::Malformed)?;
                push(s.make_bytes(), &mut n)?;
            }
        }
        // 4. Key makes.
        for &new in &new_held[..new_len] {
            if !self.held[..self.held_len].contains(&new) {
                let s = usage_to_set1(new).ok_or(Error::Malformed)?;
                push(s.make_bytes(), &mut n)?;
            }
        }

        if out.len() < n {
            return Err(Error::BufferTooSmall); // state untouched
        }
        out[..n].copy_from_slice(&tmp[..n]);
        self.held = new_held;
        self.held_len = new_len;
        self.modifiers = modifiers;
        Ok(n)
    }
}

impl Default for Translator {
    fn default() -> Self {
        Self::new()
    }
}
