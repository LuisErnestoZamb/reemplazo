/* Per-vector interrupt stubs + shared register-saving prologue.
 *
 * Contract with Rust (`idt.rs`): each stub pushes [vector][error code]
 * (dummy 0 when the CPU pushes none), `isr_common` saves all GPRs and
 * calls `interrupt_dispatch(*mut Frame)`. Stack layout low→high after
 * the GPR pushes must match `Frame` in idt.rs exactly.
 *
 * Vectors with a CPU error code (SDM Vol.3A §6.11): 8,10,11,12,13,14,
 * 17,21,29,30. Vectors >= 48 share `isr_unexpected` (PIC masks everything
 * but IRQ0, so nothing else should arrive; it reports sentinel 0xFFFF).
 */
.section .text
.code64

.macro ISR_NOERR vec
.global isr_\vec
isr_\vec:
    pushq $0                /* dummy error code */
    pushq $\vec             /* vector number */
    jmp isr_common
.endm

.macro ISR_ERR vec
.global isr_\vec
isr_\vec:
    pushq $\vec             /* CPU already pushed the error code */
    jmp isr_common
.endm

/* --- Exceptions 0..=31 ---------------------------------------------- */
ISR_NOERR 0                 /* #DE divide error */
ISR_NOERR 1                 /* #DB debug */
ISR_NOERR 2                 /* NMI */
ISR_NOERR 3                 /* #BP breakpoint */
ISR_NOERR 4                 /* #OF overflow */
ISR_NOERR 5                 /* #BR bound range */
ISR_NOERR 6                 /* #UD invalid opcode */
ISR_NOERR 7                 /* #NM device not available */
ISR_ERR   8                 /* #DF double fault */
ISR_NOERR 9                 /* coprocessor segment overrun */
ISR_ERR   10                /* #TS invalid TSS */
ISR_ERR   11                /* #NP segment not present */
ISR_ERR   12                /* #SS stack segment fault */
ISR_ERR   13                /* #GP general protection */
ISR_ERR   14                /* #PF page fault */
ISR_NOERR 15                /* reserved */
ISR_NOERR 16                /* #MF x87 FP error */
ISR_ERR   17                /* #AC alignment check */
ISR_NOERR 18                /* #MC machine check */
ISR_NOERR 19                /* #XM SIMD FP exception */
ISR_NOERR 20                /* #VE virtualization exception */
ISR_ERR   21                /* #CP control protection */
ISR_NOERR 22
ISR_NOERR 23
ISR_NOERR 24
ISR_NOERR 25
ISR_NOERR 26
ISR_NOERR 27
ISR_NOERR 28
ISR_ERR   29                /* #VC VMM communication (AMD) */
ISR_ERR   30                /* #SX security exception (AMD) */
ISR_NOERR 31

/* --- Hardware IRQs after PIC remap (master 32..=39, slave 40..=47) --- */
ISR_NOERR 32                /* IRQ0: PIT timer */
ISR_NOERR 33                /* IRQ1: keyboard */
ISR_NOERR 34                /* IRQ2: cascade */
ISR_NOERR 35                /* IRQ3: COM2 */
ISR_NOERR 36                /* IRQ4: COM1 */
ISR_NOERR 37                /* IRQ5: LPT2 */
ISR_NOERR 38                /* IRQ6: floppy */
ISR_NOERR 39                /* IRQ7: LPT1 */
ISR_NOERR 40                /* IRQ8: RTC */
ISR_NOERR 41                /* IRQ9: ACPI */
ISR_NOERR 42                /* IRQ10: SCSI/NIC */
ISR_NOERR 43                /* IRQ11: SCSI/NIC */
ISR_NOERR 44                /* IRQ12: PS/2 mouse */
ISR_NOERR 45                /* IRQ13: FPU */
ISR_NOERR 46                /* IRQ14: primary ATA */
ISR_NOERR 47                /* IRQ15: secondary ATA */

/* --- Shared fallback for vectors >= 48 ------------------------------ */
.global isr_unexpected
isr_unexpected:
    pushq $0
    pushq $0xFFFF           /* sentinel: real vector unknown here */
    jmp isr_common

/* --- Common prologue/epilogue ---------------------------------------- */
isr_common:
    pushq %rax              /* order here must match `Frame` in idt.rs */
    pushq %rcx
    pushq %rdx
    pushq %rbx
    pushq %rbp
    pushq %rsi
    pushq %rdi
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, %rdi         /* arg1: *mut Frame (points at saved r15) */
    movq %rsp, %rbx         /* keep frame pointer; old rbx is on the stack */
    andq $-16, %rsp         /* SysV: 16-byte aligned before `call` */
    call interrupt_dispatch
    movq %rbx, %rsp         /* rbx is callee-saved: frame pointer intact */
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdi
    popq %rsi
    popq %rbp
    popq %rbx
    popq %rdx
    popq %rcx
    popq %rax
    addq $16, %rsp          /* drop vector + error code */
    iretq

/* --- Stub address table for the IDT builder -------------------------- */
.section .rodata
.p2align 3
.global isr_stub_table
isr_stub_table:
    .quad isr_0
    .quad isr_1
    .quad isr_2
    .quad isr_3
    .quad isr_4
    .quad isr_5
    .quad isr_6
    .quad isr_7
    .quad isr_8
    .quad isr_9
    .quad isr_10
    .quad isr_11
    .quad isr_12
    .quad isr_13
    .quad isr_14
    .quad isr_15
    .quad isr_16
    .quad isr_17
    .quad isr_18
    .quad isr_19
    .quad isr_20
    .quad isr_21
    .quad isr_22
    .quad isr_23
    .quad isr_24
    .quad isr_25
    .quad isr_26
    .quad isr_27
    .quad isr_28
    .quad isr_29
    .quad isr_30
    .quad isr_31
    .quad isr_32
    .quad isr_33
    .quad isr_34
    .quad isr_35
    .quad isr_36
    .quad isr_37
    .quad isr_38
    .quad isr_39
    .quad isr_40
    .quad isr_41
    .quad isr_42
    .quad isr_43
    .quad isr_44
    .quad isr_45
    .quad isr_46
    .quad isr_47
    .quad isr_unexpected    /* index 48: fallback for vectors >= 48 */
