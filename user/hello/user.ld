/* User ELF layout for the first userland process.
 *
 * USER_BASE = 0x0000_0080_0000_0000 = 512 GiB = PML4[1]. The kernel's
 * ELF loader maps these PT_LOADs into the process address space; it must
 * use p_vaddr from the program headers (never a hard-coded 0x400000).
 *
 * Two PT_LOADs on purpose:
 *   - `headers` (R) holds the ELF header + program header table at
 *     USER_BASE itself (one page below the first section) — this is the
 *     page lld emits before `.text` when max-page-size=0x1000;
 *   - `user` (R|X) starts at USER_BASE + 0x1000 and contains .text (with
 *     `_start`, the ELF entry), .rodata, .data and .bss. A single writable
 *     segment keeps the first loader trivial: map p_filesz bytes, zero
 *     p_filesz..p_memsz, jump to e_entry.
 * No relocations: code is linked at its final virtual address.
 */
OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

USER_BASE = 0x0000008000000000;

PHDRS {
    headers PT_LOAD FLAGS(4); /* R   — ELF headers page */
    user    PT_LOAD FLAGS(5); /* R|X — code + rodata; the loader rejects W|X segments */
}

SECTIONS {
    /* lld places the ELF/program headers in the page immediately below
     * the first section, so this makes p_vaddr(headers)=USER_BASE and
     * e_entry=_start=USER_BASE+0x1000. */
    . = USER_BASE + 0x1000;

    .text : ALIGN(4K) {
        KEEP(*(.text.entry))
        *(.text .text.*)
    } :user

    .rodata : ALIGN(4K) {
        *(.rodata .rodata.*)
    } :user

    .data : ALIGN(4K) {
        *(.data .data.*)
    } :user

    .bss : ALIGN(4K) {
        *(COMMON)
        *(.bss .bss.*)
    } :user

    /DISCARD/ : {
        *(.eh_frame*)
        *(.comment)
        *(.note*)
    }
}
