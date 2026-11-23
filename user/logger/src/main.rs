//! Persistent bring-up log — user-space application.
//!
//! Ring 0 keeps only the disk driver and the 512-byte record layout
//! (`kernel/src/logdisk.rs`). This process does the useful work: it writes
//! its own "started" record and renders the boot records onto the VGA
//! through the hito-3 console syscalls, so a human at the machine can see
//! exactly how far the previous boot got. `cargo xtask readlog` reads the
//! same sectors from Debian after the watchdog reboots.

#![no_std]
#![no_main]

core::arch::global_asm!(include_str!("../start.S"), options(att_syntax));

use userlib as sys;

const ATTR_TITLE: u8 = 0x1F;
const ATTR_TEXT: u8 = 0x07;
const ATTR_BAD: u8 = 0x0C;

fn put_str(x: u16, y: u16, s: &[u8], attr: u8, cols: u16) {
    for (i, &c) in s.iter().enumerate() {
        let cx = x.saturating_add(i as u16);
        if cx >= cols {
            break;
        }
        let _ = sys::vga_put_cell(cx, y, c, attr);
    }
}

fn put_num(x: u16, y: u16, mut n: u32, attr: u8, cols: u16) -> u16 {
    let mut digits = [0u8; 10];
    let mut len = 0usize;
    if n == 0 {
        digits[0] = b'0';
        len = 1;
    }
    while n > 0 {
        digits[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    let mut cx = x;
    for i in (0..len).rev() {
        if cx >= cols {
            break;
        }
        let _ = sys::vga_put_cell(cx, y, digits[i], attr);
        cx += 1;
    }
    cx
}

fn die(msg: &[u8]) -> ! {
    put_str(0, 0, msg, ATTR_BAD, 80);
    let _ = sys::vga_flush();
    sys::exit(1)
}

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    let Some((cols, rows)) = sys::console_dims() else {
        die(b"logger: no VGA console")
    };
    if cols < 40 || rows < 6 {
        die(b"logger: VGA geometry too small")
    }

    // Our own record proves a CPL3 process can reach persistent storage.
    let _ = sys::log_write(b"USER_LOG: logger started");

    let _ = sys::vga_clear();
    put_str(
        0,
        0,
        b"reemplazo / boot log  [user process, ring 3]",
        ATTR_TITLE,
        cols,
    );

    let mut shown = 0u32;
    let mut y = 2u16;
    for seq in 0..24u32 {
        if y >= rows.saturating_sub(1) {
            break;
        }
        let mut record = [0u8; 512];
        if sys::log_read(seq, &mut record) < 0 {
            break;
        }
        if &record[..8] != b"RLOGv1\0\0" {
            break;
        }
        let seq_no = u16::from_le_bytes([record[8], record[9]]);
        let code = record[12];
        let cx = put_num(0, y, seq_no as u32, ATTR_TEXT, cols);
        let code_txt = [b'0' + code / 16, b'0' + code % 16];
        let _ = sys::vga_put_cell(cx.saturating_add(1), y, code_txt[0], ATTR_TEXT);
        let _ = sys::vga_put_cell(cx.saturating_add(2), y, code_txt[1], ATTR_TEXT);
        // Label is bounded to 112 bytes in the record; render the first
        // 52 so it always fits the 80-column MacBook VGA.
        let label = &record[24..76];
        put_str(cx.saturating_add(4), y, label, ATTR_TEXT, cols);
        shown += 1;
        y += 1;
    }

    let status: &[u8] = if shown > 0 {
        &b"records above are on disk (xtask readlog)"[..]
    } else {
        &b"log not provisioned - nothing written"[..]
    };
    put_str(0, rows.saturating_sub(1), status, ATTR_TITLE, cols);
    let _ = sys::vga_flush();

    // Hold the frame long enough for a human at the machine to read it.
    for _ in 0..250 {
        let _ = sys::yield_now();
    }
    sys::exit(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    put_str(0, 0, b"FATAL: logger panic", ATTR_BAD, 80);
    let _ = sys::vga_flush();
    sys::exit(1)
}
