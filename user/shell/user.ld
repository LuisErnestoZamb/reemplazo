/* User ELF layout for the hito-3 shell.
 *
 * USER_BASE = 0x0000_0080_0000_0000 (PML4[1]); e_entry = USER_BASE + 0x1000.
 * Three load segments are intended: R|X code at +0x1000, R rodata, one
 * R|W data segment holding .got + the line buffer.
 *
 * Two rust-lld details matter here (both were found by a failing boot):
 *   1. No `PHDRS` directive — rust-lld collapses declared PHDRs into a
 *      single R|X load segment, which maps the mutable buffer read-only.
 *      Deriving PT_LOADs from the section flags gives a separate RW one.
 *   2. `-C code-model=large` makes rustc emit `.ltext.*`, `.lrodata.*`,
 *      `.ldata.*` and `.lbss.*`. They must be listed explicitly: orphan
 *      sections each become their own PT_LOAD, and the U1 loader maps
 *      whole 4 KiB frames per segment (`AlreadyMapped` on a shared page).
 * Keeping `.got` and the buffer in ONE writable output section is what
 * produces a single, page-clean RW load segment.
 */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

USER_BASE = 0x0000008000000000;

SECTIONS {
    . = USER_BASE + 0x1000;

    .text : ALIGN(4K) {
        KEEP(*(.text.entry))
        *(.text .text.* .ltext .ltext.*)
    }

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.* .lrodata .lrodata.*)
    }

    . = ALIGN(4K);
    .data : {
        *(.got .got.*)
        *(.data .data.* .ldata .ldata.*)
        *(COMMON)
        *(.bss .bss.* .lbss .lbss.*)
    }

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
    }
}
