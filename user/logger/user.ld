/* User ELF layout for the persistent log — byte-for-byte the hito-3 shell
 * contract (see user/shell/user.ld for the two rust-lld gotchas). */
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
