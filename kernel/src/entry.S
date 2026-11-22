/* Boot entry for GRUB multiboot2 → long mode.
 *
 * GRUB loads this ELF64 kernel and jumps to _start in 32-bit protected
 * mode (Multiboot2 spec §3.3): EAX = 0x36d76289 magic, EBX = physical
 * address of the multiboot2 information (mbi), paging off, interrupts
 * off, A20 on, GDTR possibly invalid (must not reload segment
 * registers before our own GDT is live).
 *
 * We identity-map the first 4 GiB with 2 MiB pages (covers all 2.9 GiB
 * of the target's RAM plus low MMIO such as the framebuffer), enable
 * long mode, far-jump to 64-bit code, and call kernel_main(magic, mbi).
 */

/* --- Multiboot2 header (spec §3.1) -------------------------------------
 * Must be 8-byte aligned within the first 32768 bytes of the image file.
 * `. = 2M` + max-page-size=0x1000 in build.rs puts it at file offset
 * ~0x1000 (verified in xtask iso via grub-file). Linking at 2 MiB keeps
 * the ELF headers that share the first PT_LOAD above the BIOS ROM area. */
.section .multiboot_header, "a"
.balign 8
mb2_header_start:
    .long 0xe85250d6                          /* magic */
    .long 0                                    /* architecture: i386 protected mode */
    .long mb2_header_end - mb2_header_start    /* header_length, incl. tags */
    .long -(0xe85250d6 + (mb2_header_end - mb2_header_start)) /* checksum */
    /* terminating tag: type=0, flags=0, size=8 */
    .short 0
    .short 0
    .long 8
mb2_header_end:

/* --- 32-bit entry ------------------------------------------------------ */
.section .text.entry, "ax"
.code32
.global _start
_start:
    cli
    cld                                /* SysV: DF must be clear */

    /* Preserve the boot registers before rep stosl clobbers them. */
    movl %eax, boot_magic
    movl %ebx, boot_mbi

    movl $stack_top, %esp

    cmpl $0x36d76289, boot_magic       /* refuse to continue otherwise */
    jne .Lbad_magic

    /* Zero PML4 + PDPT + 4 page directories (6 pages of page tables);
     * the fill loop below writes every PD entry but its high dwords. */
    xorl %eax, %eax
    movl $pml4, %edi
    movl $6144, %ecx                   /* 6 * 4096 / 4 dwords */
    rep stosl

    /* PML4[0] = PDPT | PRESENT | RW */
    movl $pdpt, %eax
    orl $0x3, %eax
    movl %eax, pml4

    /* PDPT[0..3] = PD0..PD3 | PRESENT | RW → identity-map 4 GiB */
    movl $pd0, %eax
    orl $0x3, %eax
    movl %eax, pdpt
    movl $pd1, %eax
    orl $0x3, %eax
    movl %eax, pdpt + 8
    movl $pd2, %eax
    orl $0x3, %eax
    movl %eax, pdpt + 16
    movl $pd3, %eax
    orl $0x3, %eax
    movl %eax, pdpt + 24

    /* Fill 4 * 512 entries: phys | PRESENT | RW | PAGE_SIZE (2 MiB) */
    movl $pd0, %edi
    xorl %eax, %eax                    /* physical address, += 2 MiB */
    movl $2048, %ecx
.Lfill_pd:
    movl %eax, %edx
    orl $0x83, %edx                    /* P(0) | RW(1) | PS(7) */
    movl %edx, (%edi)
    addl $0x200000, %eax
    addl $8, %edi
    loop .Lfill_pd

    /* CR4 |= PAE (bit 5) */
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4

    /* CR3 = PML4 */
    movl $pml4, %eax
    movl %eax, %cr3

    /* EFER.LME |= 1 (MSR 0xc0000080) */
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x100, %eax
    wrmsr

    /* Our GDT (required before any segment reload) */
    lgdt gdt64_ptr

    /* CR0 |= PG (bit 31); PE already set by GRUB */
    movl %cr0, %eax
    orl $0x80000001, %eax
    movl %eax, %cr0

    /* Far jump → 64-bit code segment (selector 0x08) */
    ljmp $0x08, $long_mode_start

.Lbad_magic:
    hlt
    jmp .Lbad_magic

/* --- 64-bit entry ------------------------------------------------------ */
.code64
long_mode_start:
    movw $0x10, %ax                    /* data selector (GDT index 2) */
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movw %ax, %fs
    movw %ax, %gs

    /* Finish the TSS descriptor's base fields. GAS cannot shift a
     * relocatable symbol into the split base bytes, so they are patched
     * here — after `lgdt` (which copied only the pointer) and before
     * `ltr` (which reads the descriptor). */
    leaq tss(%rip), %rax
    leaq gdt64 + 40(%rip), %rdx
    movw %ax, 2(%rdx)                  /* base 15..0 */
    shrq $16, %rax
    movb %al, 4(%rdx)                  /* base 23..16 */
    shrq $8, %rax
    movb %al, 7(%rdx)                  /* base 31..24 */
    shrq $8, %rax
    movl %eax, 8(%rdx)                 /* base 63..32 (0: kernel < 4 GiB) */

    /* 64-bit TSS (GDT index 5). RSP0 is where a CPL3→CPL0 interrupt
     * switches to; it starts at the boot stack and the scheduler may
     * repoint it per task with `idt::set_tss_rsp0`. IOPB = 0x68 is one
     * past the TSS limit (0x67), so *every* port is denied to CPL3
     * (SDM Vol.3A §8.5.3); ring 0 still does I/O via IOPL=0. */
    leaq stack_top(%rip), %rax
    movq %rax, tss + 4(%rip)           /* RSP0 @ offset 4 */
    movw $0x68, tss + 0x64(%rip)       /* I/O map base @ offset 0x64 */

    /* `ltr` takes r/m16, not an immediate. Descriptor is present, DPL0,
     * type 9 (64-bit TSS available); loading it marks it busy. */
    movw $0x28, %ax
    ltr %ax

    movq $stack_top, %rsp
    xorq %rbp, %rbp

    /* System V AMD64: rdi = magic, rsi = mbi physical address */
    movl boot_magic(%rip), %edi        /* movl zero-extends into rdi */
    movl boot_mbi(%rip), %esi
    call kernel_main

.Lhang64:
    cli
    hlt
    jmp .Lhang64

/* --- GDT64: 7 slots, needed before the CS reload -----------------------
 * 0x00 null · 0x08 kernel code (DPL0) · 0x10 kernel data (DPL0) ·
 * 0x1B user code (index 3, DPL3 + RPL3) · 0x23 user data (index 4, DPL3) ·
 * 0x28/0x30 64-bit TSS (index 5, DPL0). A long-mode system descriptor
 * spans TWO slots (SDM Vol.3A §8.2.3): the first 8 bytes hold limit,
 * base 31..0 and type/P, the second hold base 63..32 + 4 reserved zero
 * bytes; slot 0x30 is therefore not usable as a segment. The TSS base
 * bytes are patched in `long_mode_start` (GAS cannot shift a relocatable
 * symbol). Every code/data entry is flat; the user data descriptor keeps
 * D/B=0 as the kernel one does (long mode ignores it).
 */
.section .rodata, "a"
.balign 8
gdt64:
    .quad 0x0000000000000000           /* 0x00: null */
    .quad 0x00209a0000000000           /* 0x08: code, L=1, P, DPL0, exec/read */
    .quad 0x0000920000000000           /* 0x10: data, P, DPL0, read/write */
    .quad 0x0020fa0000000000           /* 0x18/0x1B: code, L=1, P, DPL3 */
    .quad 0x0000f20000000000           /* 0x20/0x23: data, P, DPL3 */
    .word tss_end - tss - 1            /* TSS limit = 104 - 1 = 0x67 */
    .word 0                            /* base 15..0: patched at boot */
    .byte 0                            /* base 23..16: patched at boot */
    .byte 0x89                         /* type=9 (64-bit TSS available), S=0, P=1 */
    .byte 0x00                         /* limit 19..16 = 0, G/AVL/L = 0 */
    .byte 0                            /* base 31..24: patched at boot */
    .long 0                            /* base 63..32: patched at boot (0) */
    .long 0                            /* reserved half of the 16-byte TSS desc */
gdt64_end:
gdt64_ptr:
    .word gdt64_end - gdt64 - 1        /* limit = 7*8 - 1 = 55 */
    .long gdt64                        /* base (kernel < 4 GiB) */

/* --- Data --------------------------------------------------------------- */
.section .bss, "aw", @nobits
.balign 4096
.global pml4                           /* the ELF loader must map PML4[1] */
pml4: .skip 4096
pdpt: .skip 4096
pd0:  .skip 4096
pd1:  .skip 4096
pd2:  .skip 4096
pd3:  .skip 4096

boot_magic: .skip 4
boot_mbi:   .skip 4

/* 64-bit TSS, 104 bytes (SDM Vol.3A §8.2.3). RSP0 (+4) and the I/O map
 * base (+0x64) are initialised in `long_mode_start` before `ltr`; the
 * rest stays zero (IST unused, no other privilege stacks). */
.balign 16
.global tss
tss:
    .skip 104
tss_end:

/* Guard gap between the stack and the page tables above it: a stack
 * overflow must eat this padding before it can corrupt a page-table
 * entry. The tables' last page holds pd3, which maps the e1000 MMIO
 * window (0xFExxxxxx) — a corrupted PDE faults on the next MMIO
 * access, and with no IDT armed yet that is a double fault and a
 * triple fault (QEMU exits under -no-reboot). The kernel fills this
 * gap with a canary at boot and re-checks it on every serial line. */
.balign 16
.global guard_start
guard_start:
.skip 16384
.global guard_end
guard_end:

.balign 16
/* 128 KiB: the TLS handshake (record buffers, verifier state, fmt
 * frames) is the deepest chain so far; measured ~44 KiB of the old
 * 64 KiB was in use when the stack touched pd3 (see guard above). */
stack_bottom: .skip 131072
stack_top:
