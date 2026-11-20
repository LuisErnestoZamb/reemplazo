//! 8259A dual PIC: remap IRQs off the CPU exception vectors and mask
//! everything except IRQ0 (the PIT timer).
//!
//! GRUB leaves the PIC at its power-on offsets (IRQ0 → vector 8), which
//! collides with #DF. Remap to 32..=47 per the standard sequence
//! (OSDev / Intel 8259A datasheet).

use crate::port::outb;

const PIC_MASTER_CMD: u16 = 0x20;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_CMD: u16 = 0xA0;
const PIC_SLAVE_DATA: u16 = 0xA1;

/// ICW1: begin initialization + expect ICW4.
const ICW1_INIT: u8 = 0x11;
/// ICW4: 8086 mode (not 8080/Special Fully Nested).
const ICW4_8086: u8 = 0x01;

/// Remap master to 0x20..=0x27, slave to 0x28..=0x2F, mask all lines
/// except IRQ0 (timer). Idempotent enough for boot: call once before `sti`.
pub fn init() {
    // SAFETY: standard PIC command/data ports; single-core boot, IF=0.
    unsafe {
        outb(PIC_MASTER_CMD, ICW1_INIT);
        outb(PIC_SLAVE_CMD, ICW1_INIT);
        outb(PIC_MASTER_DATA, 0x20); // master vectors start at 32
        outb(PIC_SLAVE_DATA, 0x28); // slave vectors start at 40
        outb(PIC_MASTER_DATA, 0x04); // slave is on IRQ2 (cascade)
        outb(PIC_SLAVE_DATA, 0x02); // cascade identity: slave on IRQ2
        outb(PIC_MASTER_DATA, ICW4_8086);
        outb(PIC_SLAVE_DATA, ICW4_8086);

        // Masks: master = all masked except bit0 (IRQ0); slave = all masked.
        outb(PIC_MASTER_DATA, 0xFE);
        outb(PIC_SLAVE_DATA, 0xFF);
    }
}

/// Send End-Of-Interrupt for hardware IRQ `irq` (0..=15). IRQs 8..=15 must
/// also EOI the master after the slave.
pub fn eoi(irq: u8) {
    // SAFETY: standard EOI ports; called from interrupt context only.
    unsafe {
        if irq >= 8 {
            outb(PIC_SLAVE_CMD, 0x20);
        }
        outb(PIC_MASTER_CMD, 0x20);
    }
}
