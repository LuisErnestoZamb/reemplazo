//! Adversarial host tests for `usbwire`: every refusal the parser and
//! the HID boot-report translator can hit, plus translation round-trips
//! over the printable range.
//!
//! The reference fixtures are QEMU v10.0.0 `hw/usb/dev-hid.c`'s
//! `usb-kbd` descriptors byte-for-byte (device descriptor
//! `bcdUSB 0x0100`, maxpkt0 8, config total 34, interface 03/01/01,
//! HID report length 63, endpoint 0x81 interrupt-IN, interval 10).

use usbwire::{
    BootKeyboard, BootReport, DEVICE_DESCRIPTOR_LEN, DeviceDescriptor, Error, Set1, Translator,
    find_boot_keyboard, parse_boot_report, parse_device, usage_to_set1,
};

// ---------------------------------------------------------------------------
// Fixtures (QEMU usb-kbd, dev-hid.c)
// ---------------------------------------------------------------------------

/// QEMU `desc_device_keyboard` as it comes off the wire (full speed).
fn device_desc() -> Vec<u8> {
    vec![
        0x12, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x08, // bLength, type, bcdUSB 1.00, class 0/0/0, maxpkt0 8
        0x27, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, // vid 0627, pid 0001, bcdDevice, iManuf/iProduct
        0x00, 0x01, // iSerialNumber, bNumConfigurations
    ]
}

/// QEMU `desc_device_keyboard` + `desc_iface_keyboard`: the 34-byte
/// configuration (config 9 + interface 9 + HID 9 + endpoint 7).
fn config_desc() -> Vec<u8> {
    vec![
        // Configuration: total 34, 1 interface, value 1, 0x80 attrs, 100 mA.
        0x09, 0x02, 0x22, 0x00, 0x01, 0x01, 0x00, 0x80, 0x32,
        // Interface 0, alt 0, 1 endpoint, HID boot keyboard (3/1/1).
        0x09, 0x04, 0x00, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00,
        // HID descriptor: bcdHID 1.11, 1 report descriptor, 63 bytes.
        0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0x00,
        // Endpoint 0x81 interrupt-IN, 8 bytes, interval 10.
        0x07, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0a,
    ]
}

/// Standard 8-byte boot report: modifiers, reserved, six usage slots.
fn report(modifiers: u8, keys: [u8; 6]) -> Result<BootReport, Error> {
    let mut buf = [0u8; 8];
    buf[0] = modifiers;
    buf[2..8].copy_from_slice(&keys);
    parse_boot_report(&buf)
}

/// Translate one report and return the bytes emitted.
fn emit(t: &mut Translator, r: &BootReport) -> Vec<u8> {
    let mut out = [0u8; Translator::MAX_BYTES];
    let n = t.translate(r, &mut out).expect("buffer is MAX_BYTES");
    out[..n].to_vec()
}

// ---------------------------------------------------------------------------
// Device descriptor
// ---------------------------------------------------------------------------

#[test]
fn device_descriptor_parses_qemu_shape() {
    let d = parse_device(&device_desc()).expect("valid QEMU usb-kbd descriptor");
    assert_eq!(
        d,
        DeviceDescriptor {
            bcd_usb: 0x0100,
            device_class: 0x00,
            device_subclass: 0x00,
            device_protocol: 0x00,
            max_packet_size0: 8,
            vendor_id: 0x0627,
            product_id: 0x0001,
            bcd_device: 0x0000,
            num_configurations: 1,
        }
    );
}

#[test]
fn device_descriptor_truncated_at_every_length() {
    let full = device_desc();
    for len in 0..DEVICE_DESCRIPTOR_LEN {
        assert_eq!(
            parse_device(&full[..len]),
            Err(Error::Truncated),
            "length {len} must be refused"
        );
    }
    assert!(parse_device(&full[..DEVICE_DESCRIPTOR_LEN]).is_ok());
}

#[test]
fn device_descriptor_rejects_wrong_length_or_type() {
    let mut d = device_desc();
    d[0] = 17; // bLength lies
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[0] = 0;
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[1] = 0x02; // configuration type in a device descriptor
    assert_eq!(parse_device(&d), Err(Error::Malformed));
}

#[test]
fn device_descriptor_rejects_illegal_maxpacket_or_versions() {
    let mut d = device_desc();
    d[7] = 0; // bMaxPacketSize0 = 0
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[7] = 12; // not one of 8/16/32/64 (USB 2.0 §9.6.2.1)
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[7] = 65;
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[2] = 0;
    d[3] = 0; // bcdUSB 0x0000 is not a USB release
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    let mut d = device_desc();
    d[17] = 0; // zero configurations
    assert_eq!(parse_device(&d), Err(Error::Malformed));
    // A real release number above 1.10 must be accepted (Apple
    // keyboards commonly report 0x0110/0x0200).
    let mut d = device_desc();
    d[2] = 0x00;
    d[3] = 0x02;
    assert_eq!(parse_device(&d).unwrap().bcd_usb, 0x0200);
}

// ---------------------------------------------------------------------------
// Configuration walk
// ---------------------------------------------------------------------------

#[test]
fn config_walk_finds_qemu_boot_keyboard() {
    let kbd = find_boot_keyboard(&config_desc()).expect("QEMU usb-kbd config");
    assert_eq!(
        kbd,
        BootKeyboard {
            config_value: 1,
            interface_number: 0,
            endpoint: usbwire::EndpointDescriptor {
                address: 0x81,
                attributes: 0x03,
                max_packet_size: 8,
                interval: 10,
            },
            hid: usbwire::HidDescriptor {
                bcd_hid: 0x0111,
                report_descriptor_length: 63,
            },
        }
    );
}

#[test]
fn config_total_larger_than_buffer_is_truncated() {
    let mut cfg = config_desc();
    cfg[2] = 0x40; // wTotalLength 64 > 34-byte buffer
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Truncated));
    // One byte short of the declared total is also truncation.
    let full = config_desc();
    assert_eq!(find_boot_keyboard(&full[..33]), Err(Error::Truncated));
}

#[test]
fn config_total_too_small_cuts_a_descriptor() {
    let mut cfg = config_desc();
    cfg[2] = 0x1C; // 28: ends mid-HID descriptor (9+9+9 = 27, +7 endpoint)
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Truncated));
    // A total that lands exactly between descriptors but before the
    // endpoint leaves the interface claiming an endpoint the walk never
    // saw — a refusal, not a guess (Malformed via the count check).
    let mut cfg = config_desc();
    cfg[2] = 0x12; // 18: config + interface only
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // And a total below the 9-byte header is malformed.
    let mut cfg = config_desc();
    cfg[2] = 0x04;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn config_header_type_and_length_are_enforced() {
    let mut cfg = config_desc();
    cfg[0] = 8; // bLength != 9
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    let mut cfg = config_desc();
    cfg[1] = 0x01; // device type inside a configuration
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    let mut cfg = config_desc();
    cfg[4] = 0; // bNumInterfaces = 0
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    let mut cfg = config_desc();
    cfg[5] = 0; // bConfigurationValue 0 is the unconfigured state
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    assert_eq!(find_boot_keyboard(&[]), Err(Error::Truncated));
    assert_eq!(find_boot_keyboard(&[0u8; 8]), Err(Error::Truncated));
}

#[test]
fn zero_or_one_byte_descriptor_is_malformed_not_an_infinite_loop() {
    // bLength 0 would spin the walk forever; bLength 1 cannot advance.
    for bad in [0u8, 1] {
        let mut cfg = config_desc();
        cfg[18] = bad; // the interface descriptor's bLength
        assert_eq!(
            find_boot_keyboard(&cfg),
            Err(Error::Malformed),
            "bLength {bad}"
        );
    }
    // A descriptor whose bLength runs past wTotalLength is truncation.
    let mut cfg = config_desc();
    cfg[18] = 0x40; // interface claims 64 bytes inside a 34-byte total
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Truncated));
}

#[test]
fn wrong_interface_class_is_refused() {
    // Mass storage (08/06/50): not a keyboard. (Interface descriptor
    // occupies bytes 9..18: number 11, alt 12, numeps 13, class 14,
    // subclass 15, protocol 16.)
    let mut cfg = config_desc();
    cfg[14] = 0x08;
    cfg[15] = 0x06;
    cfg[16] = 0x50;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NotBootKeyboard));
    // HID class but subclass 0 (non-boot).
    let mut cfg = config_desc();
    cfg[15] = 0x00;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NotBootKeyboard));
    // Boot subclass but protocol 2 (mouse).
    let mut cfg = config_desc();
    cfg[15] = 0x01;
    cfg[16] = 0x02;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NotBootKeyboard));
    // Alternate setting 1 is not the boot setting.
    let mut cfg = config_desc();
    cfg[12] = 0x01;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NotBootKeyboard));
}

#[test]
fn boot_keyboard_interface_without_hid_descriptor_is_malformed() {
    let mut cfg = config_desc();
    cfg[19] = 0x20; // HID slot becomes a vendor-defined descriptor type
    // The interface now claims boot keyboard but carries no HID
    // descriptor: structurally broken, not "some other device".
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn zero_endpoints_is_no_interrupt_in() {
    // Config + interface + HID only (27 bytes), bNumEndpoints 0: the
    // interface is a boot keyboard with nothing to poll.
    let mut cfg = config_desc();
    cfg.truncate(27);
    cfg[2] = 27;
    cfg[13] = 0; // bNumEndpoints
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NoInterruptIn));
}

#[test]
fn declared_endpoint_count_must_match_the_walk() {
    // Endpoint descriptor present but bNumEndpoints says 0: lying.
    let mut cfg = config_desc();
    cfg[13] = 0;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // Claims 2, walk finds 1.
    let mut cfg = config_desc();
    cfg[13] = 2;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn endpoint_must_be_interrupt_in() {
    // Interrupt-OUT: direction wrong. (Endpoint at bytes 27..34:
    // bLength 27, type 28, address 29, attributes 30, size 31..33,
    // interval 33.)
    let mut cfg = config_desc();
    cfg[29] = 0x01;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NoInterruptIn));
    // Bulk-IN (attributes 0b10): transfer type wrong.
    let mut cfg = config_desc();
    cfg[30] = 0x02;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NoInterruptIn));
    // Control-IN (0b00).
    let mut cfg = config_desc();
    cfg[30] = 0x00;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::NoInterruptIn));
}

#[test]
fn endpoint_bounds_are_enforced() {
    // wMaxPacketSize 0.
    let mut cfg = config_desc();
    cfg[31] = 0;
    cfg[32] = 0;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // wMaxPacketSize 128 > 64 (full-speed interrupt bound).
    let mut cfg = config_desc();
    cfg[31] = 0x80;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // Reserved bits 15:11 set (HS-only transactions-per-microframe).
    let mut cfg = config_desc();
    cfg[32] = 0x08; // bit 11 of the wMaxPacketSize u16
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // bInterval 0 is illegal full-speed (USB 2.0 §9.6.6).
    let mut cfg = config_desc();
    cfg[33] = 0;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // Endpoint bLength 9 (audio form) refused: pad the total so the
    // framing check reads the descriptor instead of running off it.
    let mut cfg = config_desc();
    cfg.push(0);
    cfg.push(0);
    cfg[2] = 36;
    cfg[27] = 9;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn hid_descriptor_lengths_are_validated() {
    // HID descriptor occupies bytes 18..27: bLength 18, type 19,
    // bcdHID 20..22, country 22, bNumDescriptors 23, report type 24,
    // wDescriptorLength 25..27.
    // Report length 0: nothing to declare.
    let mut cfg = config_desc();
    cfg[25] = 0;
    cfg[26] = 0;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));

    // bLength 9 but bNumDescriptors 2 → needs 12 bytes.
    let mut cfg = config_desc();
    cfg[23] = 2;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // bNumDescriptors 0 → no report length declared at all.
    let mut cfg = config_desc();
    cfg[23] = 0;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // No 0x22 (report) entry: only a physical descriptor declared.
    let mut cfg = config_desc();
    cfg[24] = 0x23;
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
    // Report length above our bound.
    let mut cfg = config_desc();
    cfg[25] = 0x01;
    cfg[26] = 0x10; // 0x1001 = 4097 > 1024
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn report_descriptor_is_never_consumed() {
    // The configuration carries only the HID descriptor's *declaration*
    // of the report descriptor (63 bytes); no report-descriptor bytes
    // exist anywhere in the buffer, and the walk must still succeed —
    // boot protocol does not fetch or parse it.
    let cfg = config_desc();
    assert!(cfg.len() == 34);
    let kbd = find_boot_keyboard(&cfg).expect("declaration only is enough");
    assert_eq!(kbd.hid.report_descriptor_length, 63);
}

#[test]
fn device_descriptor_type_inside_config_is_refused() {
    let mut cfg = config_desc();
    cfg[19] = 0x01; // HID slot claims DEVICE descriptor type
    // Framing still fine (bLength 9); the type check fires.
    assert_eq!(find_boot_keyboard(&cfg), Err(Error::Malformed));
}

#[test]
fn first_valid_boot_keyboard_interface_wins() {
    // Two interfaces: mass storage first, keyboard second — the walker
    // must skip the non-candidate and still find the keyboard.
    let mut cfg = Vec::new();
    cfg.extend_from_slice(&[
        0x09, 0x02, 0x32, 0x00, 0x02, 0x01, 0x00, 0x80, 0x32, // total 50, 2 ifaces
        0x09, 0x04, 0x00, 0x00, 0x01, 0x08, 0x06, 0x50, 0x00, // iface 0: mass storage
        0x07, 0x05, 0x81, 0x02, 0x40, 0x00, 0x00, // bulk-IN endpoint
        0x09, 0x04, 0x01, 0x00, 0x01, 0x03, 0x01, 0x01, 0x00, // iface 1: boot kbd
        0x09, 0x21, 0x11, 0x01, 0x00, 0x01, 0x22, 0x3f, 0x00, // HID, 63 bytes
        0x07, 0x05, 0x81, 0x03, 0x08, 0x00, 0x0a, // interrupt-IN
    ]);
    assert_eq!(cfg.len(), 50);
    let kbd = find_boot_keyboard(&cfg).expect("second interface is a keyboard");
    assert_eq!(kbd.interface_number, 1);
    assert_eq!(kbd.config_value, 1);
}

// ---------------------------------------------------------------------------
// Boot report parsing
// ---------------------------------------------------------------------------

#[test]
fn boot_report_parses_eight_bytes() {
    let r = report(0x02, [0x04, 0, 0, 0, 0, 0]).expect("8-byte report");
    assert_eq!(r.modifiers, 0x02);
    assert_eq!(r.keys, [0x04, 0, 0, 0, 0, 0]);
    assert!(!r.phantom);
}

#[test]
fn boot_report_length_is_exactly_eight() {
    assert_eq!(parse_boot_report(&[0u8; 7]), Err(Error::Truncated));
    assert_eq!(parse_boot_report(&[0u8; 9]), Err(Error::Malformed));
    assert_eq!(parse_boot_report(&[]), Err(Error::Truncated));
}

#[test]
fn rollover_error_codes_mark_phantom() {
    // Full ErrorRollOver (0x01 in every slot).
    let r = report(0, [0x01; 6]).expect("8 bytes");
    assert!(r.phantom);
    // POSTFail and ErrorUndefined too.
    assert!(report(0, [0x02, 0, 0, 0, 0, 0]).unwrap().phantom);
    assert!(report(0, [0, 0, 0, 0, 0x03, 0]).unwrap().phantom);
    // Usage 0x04 ('A') is a real key, not an error.
    assert!(!report(0, [0x04, 0, 0, 0, 0, 0]).unwrap().phantom);
}

// ---------------------------------------------------------------------------
// Translation: make/break, modifiers, E0, phantom, drops
// ---------------------------------------------------------------------------

#[test]
fn simple_press_and_release_round_trip() {
    let mut t = Translator::new();
    let a = report(0, [0x04, 0, 0, 0, 0, 0]).unwrap(); // 'A' usage
    assert_eq!(emit(&mut t, &a), vec![0x1E]); // set-1 make of 'a'
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0x9E]); // break = make | 0x80
}

#[test]
fn modifier_only_report_emits_shift_make_break() {
    let mut t = Translator::new();
    let shift = report(0x02, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &shift), vec![0x2A]); // LShift make
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0xAA]); // LShift break
}

#[test]
fn modifier_in_key_array_is_unioned_not_doubled() {
    let mut t = Translator::new();
    // LCtrl reported in *both* the modifier byte (bit 0) and a key
    // slot (usage 0xE0): exactly one make.
    let r = report(0x01, [0xE0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &r), vec![0x1D]); // LCtrl make, once
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0x9D]); // and one break
}

#[test]
fn modifier_only_in_key_array_still_tracks() {
    let mut t = Translator::new();
    // Modifier byte empty, usage 0xE5 (RShift) only in the array.
    let r = report(0, [0xE5, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &r), vec![0x36]); // RShift make
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0xB6]); // RShift break
}

#[test]
fn phantom_report_is_refused_and_state_survives() {
    let mut t = Translator::new();
    let a = report(0, [0x04, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &a), vec![0x1E]); // hold 'a'
    // Phantom (rollover) while 'a' is held: no bytes, no state change.
    let phantom = report(0, [0x01; 6]).unwrap();
    assert_eq!(emit(&mut t, &phantom), Vec::<u8>::new());
    // Another phantom: still nothing.
    assert_eq!(emit(&mut t, &phantom), Vec::<u8>::new());
    // Back to normal with 'a' still down: still nothing (unchanged).
    let still = report(0, [0x04, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &still), Vec::<u8>::new());
    // Release is still delivered correctly after the glitch.
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0x9E]);
}

#[test]
fn unknown_usage_is_dropped_without_polluting_state() {
    let mut t = Translator::new();
    // Usage 0x90: outside our table (F13+/media range) → dropped.
    let unk = report(0, [0x90, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &unk), Vec::<u8>::new());
    // The unknown key disappearing must not emit a stray break.
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), Vec::<u8>::new());
    // And a known key still works afterwards.
    let a = report(0, [0x04, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &a), vec![0x1E]);
}

#[test]
fn usage_zero_slots_are_ignored() {
    let mut t = Translator::new();
    let empty = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &empty), Vec::<u8>::new());
    assert_eq!(emit(&mut t, &empty), Vec::<u8>::new());
}

#[test]
fn duplicate_slots_produce_one_make_one_break() {
    let mut t = Translator::new();
    // Same usage in two slots (a malformed-but-harmless report).
    let r = report(0, [0x04, 0x04, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &r), vec![0x1E]);
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0x9E]);
}

#[test]
fn e0_extended_arrow_mapping() {
    let mut t = Translator::new();
    // HID 0x52 = Up Arrow → set-1 E0 48 (docs/hardware.md §2.4).
    let up = report(0, [0x52, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &up), vec![0xE0, 0x48]);
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0xE0, 0xC8]); // E0 (48|0x80)
}

#[test]
fn shift_plus_key_orders_modifier_before_key() {
    let mut t = Translator::new();
    // Shift+'A' arriving in one report: modifier make first.
    let r = report(0x02, [0x04, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &r), vec![0x2A, 0x1E]);
    // Releasing both in one report: key break first, then modifier.
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0x9E, 0xAA]);
}

#[test]
fn multi_key_rollover_diffs_correctly() {
    let mut t = Translator::new();
    let abc = report(0, [0x04, 0x05, 0x06, 0, 0, 0]).unwrap(); // a,b,c
    assert_eq!(emit(&mut t, &abc), vec![0x1E, 0x30, 0x2E]);
    // Release 'a', keep b,c: one break.
    let bc = report(0, [0x05, 0x06, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &bc), vec![0x9E]);
    // Press 'd' alongside: one make.
    let bcd = report(0, [0x05, 0x06, 0x07, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &bcd), vec![0x20]);
    // Release everything.
    let none = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(emit(&mut t, &none), vec![0xB0, 0xAE, 0xA0]); // b,c,d breaks
}

#[test]
fn buffer_too_small_refuses_without_consuming_state() {
    let mut t = Translator::new();
    // Up Arrow needs the 2-byte `E0 48` make — a 1-byte buffer cannot
    // hold it.
    let up = report(0, [0x52, 0, 0, 0, 0, 0]).unwrap();
    let mut tiny = [0u8; 1];
    assert_eq!(t.translate(&up, &mut tiny), Err(Error::BufferTooSmall));
    // State was not committed: a big-enough retry emits the full
    // transition (the arrow make is still pending).
    let mut out = [0u8; Translator::MAX_BYTES];
    let n = t.translate(&up, &mut out).unwrap();
    assert_eq!(&out[..n], &[0xE0, 0x48]);
    // …and a repeat of the same report is now a no-op.
    let n2 = t.translate(&up, &mut out).unwrap();
    assert_eq!(n2, 0);
}

#[test]
fn max_bytes_bound_holds_for_full_chord() {
    // Worst case in one transition: 6 extended keys released (12),
    // 6 extended keys pressed (12), and every modifier bit changing —
    // half released, half pressed — with the E0-prefixed ones spread
    // across both sides (12). Total 36 = MAX_BYTES exactly.
    let mut t = Translator::new();
    let first = report(
        0x55,                                 // bits 0,2,4,6 down (LCtrl, LAlt, RCtrl, RAlt)
        [0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E], // Insert..PageDown (all E0)
    )
    .unwrap();
    let n1 = t
        .translate(&first, &mut [0u8; Translator::MAX_BYTES])
        .unwrap();
    assert!(n1 <= Translator::MAX_BYTES, "first chord {n1}");
    let second = report(
        0xAA,                                 // bits 1,3,5,7 down (LShift, LGui, RShift, RGui)
        [0x4F, 0x50, 0x51, 0x52, 0x54, 0x58], // arrows + keypad /, Enter (all E0)
    )
    .unwrap();
    let mut out = [0u8; Translator::MAX_BYTES];
    let n2 = t.translate(&second, &mut out).unwrap();
    assert_eq!(n2, Translator::MAX_BYTES);
}

// ---------------------------------------------------------------------------
// Translation table round-trips (printable US range)
// ---------------------------------------------------------------------------

/// Independent expected set-1 make codes for the printable range,
/// transcribed from `docs/hardware.md` §2.4 (which cites OSDev's
/// Scan Code Set 1 table). Kept separate from `usage_to_set1` so a
/// typo cannot cancel itself out.
const EXPECTED_PRINTABLE: &[(u8, u8)] = &[
    // HID usage → set-1 make code
    (0x04, 0x1E), // A
    (0x05, 0x30), // B
    (0x06, 0x2E), // C
    (0x07, 0x20), // D
    (0x08, 0x12), // E
    (0x09, 0x21), // F
    (0x0A, 0x22), // G
    (0x0B, 0x23), // H
    (0x0C, 0x17), // I
    (0x0D, 0x24), // J
    (0x0E, 0x25), // K
    (0x0F, 0x26), // L
    (0x10, 0x32), // M
    (0x11, 0x31), // N
    (0x12, 0x18), // O
    (0x13, 0x19), // P
    (0x14, 0x10), // Q
    (0x15, 0x13), // R
    (0x16, 0x1F), // S
    (0x17, 0x14), // T
    (0x18, 0x16), // U
    (0x19, 0x2F), // V
    (0x1A, 0x11), // W
    (0x1B, 0x2D), // X
    (0x1C, 0x15), // Y
    (0x1D, 0x2C), // Z
    (0x1E, 0x02), // 1
    (0x1F, 0x03), // 2
    (0x20, 0x04), // 3
    (0x21, 0x05), // 4
    (0x22, 0x06), // 5
    (0x23, 0x07), // 6
    (0x24, 0x08), // 7
    (0x25, 0x09), // 8
    (0x26, 0x0A), // 9
    (0x27, 0x0B), // 0
    (0x28, 0x1C), // Enter
    (0x29, 0x01), // Esc
    (0x2A, 0x0E), // Backspace
    (0x2B, 0x0F), // Tab
    (0x2C, 0x39), // Space
    (0x2D, 0x0C), // -
    (0x2E, 0x0D), // =
    (0x2F, 0x1A), // [
    (0x30, 0x1B), // ]
    (0x31, 0x2B), // backslash
    (0x33, 0x27), // ;
    (0x34, 0x28), // '
    (0x35, 0x29), // `
    (0x36, 0x33), // ,
    (0x37, 0x34), // .
    (0x38, 0x35), // /
];

#[test]
fn printable_range_round_trips_make_and_break() {
    for &(usage, make) in EXPECTED_PRINTABLE {
        let s = usage_to_set1(usage).unwrap_or_else(|| panic!("usage {usage:#04x} mapped"));
        assert_eq!(s.code, make, "usage {usage:#04x}");
        assert!(!s.extended, "usage {usage:#04x} is a base code");
        // Break = make | 0x80 (docs/hardware.md §2.4).
        let (buf, n) = s.break_bytes();
        assert_eq!(buf[0], make | 0x80);
        assert_eq!(n, 1);

        // Full round trip through the translator: press → make,
        // release → break.
        let mut t = Translator::new();
        let press = report(0, [usage, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(emit(&mut t, &press), vec![make], "press usage {usage:#04x}");
        let release = report(0, [0, 0, 0, 0, 0, 0]).unwrap();
        assert_eq!(
            emit(&mut t, &release),
            vec![make | 0x80],
            "release usage {usage:#04x}"
        );
    }
}

#[test]
fn extended_range_maps_to_the_e0_list() {
    // docs/hardware.md §2.4 "Extended (E0) keys" + keypad/lock rows.
    let expected: &[(u8, Set1)] = &[
        (
            0x49,
            Set1 {
                code: 0x52,
                extended: true,
            },
        ), // Insert
        (
            0x4A,
            Set1 {
                code: 0x47,
                extended: true,
            },
        ), // Home
        (
            0x4B,
            Set1 {
                code: 0x49,
                extended: true,
            },
        ), // PageUp
        (
            0x4C,
            Set1 {
                code: 0x53,
                extended: true,
            },
        ), // Delete
        (
            0x4D,
            Set1 {
                code: 0x4F,
                extended: true,
            },
        ), // End
        (
            0x4E,
            Set1 {
                code: 0x51,
                extended: true,
            },
        ), // PageDown
        (
            0x4F,
            Set1 {
                code: 0x4D,
                extended: true,
            },
        ), // Right
        (
            0x50,
            Set1 {
                code: 0x4B,
                extended: true,
            },
        ), // Left
        (
            0x51,
            Set1 {
                code: 0x50,
                extended: true,
            },
        ), // Down
        (
            0x52,
            Set1 {
                code: 0x48,
                extended: true,
            },
        ), // Up
        (
            0x54,
            Set1 {
                code: 0x35,
                extended: true,
            },
        ), // keypad /
        (
            0x58,
            Set1 {
                code: 0x1C,
                extended: true,
            },
        ), // keypad Enter
        (
            0x39,
            Set1 {
                code: 0x3A,
                extended: false,
            },
        ), // CapsLock
        (
            0x44,
            Set1 {
                code: 0x57,
                extended: false,
            },
        ), // F11
        (
            0x45,
            Set1 {
                code: 0x58,
                extended: false,
            },
        ), // F12
        (
            0x47,
            Set1 {
                code: 0x46,
                extended: false,
            },
        ), // ScrollLock
        (
            0x53,
            Set1 {
                code: 0x45,
                extended: false,
            },
        ), // NumLock
        (
            0x55,
            Set1 {
                code: 0x37,
                extended: false,
            },
        ), // keypad *
        (
            0x5F,
            Set1 {
                code: 0x47,
                extended: false,
            },
        ), // keypad 7
        (
            0x62,
            Set1 {
                code: 0x52,
                extended: false,
            },
        ), // keypad 0
        (
            0x63,
            Set1 {
                code: 0x53,
                extended: false,
            },
        ), // keypad .
    ];
    for &(usage, want) in expected {
        assert_eq!(usage_to_set1(usage), Some(want), "usage {usage:#04x}");
    }
    // Modifier usages have their own table.
    assert_eq!(
        usbwire::modifier_to_set1(0xE0),
        Some(Set1 {
            code: 0x1D,
            extended: false
        })
    );
    assert_eq!(
        usbwire::modifier_to_set1(0xE3),
        Some(Set1 {
            code: 0x5B,
            extended: true
        })
    );
    assert_eq!(
        usbwire::modifier_to_set1(0xE7),
        Some(Set1 {
            code: 0x5C,
            extended: true
        })
    );
    assert_eq!(usbwire::modifier_to_set1(0xDF), None);
    assert_eq!(usbwire::modifier_to_set1(0xE8), None);
}

#[test]
fn deliberately_unmapped_usages_return_none() {
    for usage in [
        0x00u8, // no event
        0x01,
        0x02,
        0x03, // error codes (phantom territory)
        0x32, // Non-US # (no set-1 code in our table)
        0x46, // PrintScreen: multi-byte E0 sequence
        0x48, // Pause: E1 sequence
        0x64,
        0x65,
        0x66,     // power/keypad =/F13 boundary — unmapped
        0x90,     // media/undefined range
        0xE0 - 1, // just below the modifier block
        0xFF,     // out of page
    ] {
        assert_eq!(
            usage_to_set1(usage),
            None,
            "usage {usage:#04x} must be dropped"
        );
    }
}
