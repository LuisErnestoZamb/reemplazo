/* Kernel linker script: GRUB multiboot2 loads ELF64 segments at p_paddr.
 *
 * `. = 2M` (not 1M): with max-page-size=0x1000 (see build.rs) the first
 * PT_LOAD maps the ELF headers just below `.`, so at 1M the headers would
 * land in 0xFF000 — the BIOS ROM region — and header writes could corrupt
 * the legacy BIOS/CSM code GRUB still uses. At 2M they land at 0x1FF000,
 * plain RAM. Entry (GRUB, ELF64) must stay < 4 GiB — it does.
 */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

SECTIONS {
    . = 2M;
    /* Used by the frame allocator (memory.rs) to reserve the kernel image
     * — incl. .bss: boot stack, page tables, bitmap — from free RAM. */
    kernel_start = .;

    .multiboot_header : {
        KEEP(*(.multiboot_header))
    }

    .text : ALIGN(4K) {
        *(.text.entry)
        *(.text .text.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4K) {
        *(.data .data.*)
    }

    .bss : ALIGN(4K) {
        *(COMMON)
        *(.bss .bss.*)
    }

    /* Page-align the end so whole-frame reservation covers everything. */
    . = ALIGN(4K);
    kernel_end = .;

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
    }
}
